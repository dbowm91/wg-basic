# Distribution M003 — Eggpack Release Pipeline and Signed Draft Handoff

Status: active — Eggpack identity seam unblocked at reviewed revision `d61ca71fc0112be63e7e8ba31ba8fa2b1ce5a628`.

Source roadmap:

- `plans/subsystems/distribution-install-update-roadmap.md#7-m003--eggpack-producer-pipeline-and-signed-draft-release`

Canonical architecture:

- `plans/adr/006-distribution-install-authenticity-and-update.md`

Primary class: release engineering / producer evidence / supply-chain handoff

Hard dependencies:

- Distribution M002 strict closure;
- M001 release target/trust contracts remain unchanged.

External production-publication prerequisite:

- maintainer-provisioned production Minisign public key is required before a draft can be called production-signed.

Fixture signing may qualify the pipeline before that prerequisite.

## 1. Objective

Make release production deterministic and consumer-compatible using Eggpack, while keeping private signing authority outside ordinary repository CI.

M003 creates and qualifies a draft-release workflow and signing handoff.

M003 MUST NOT automatically publish a public production release.

## 2. Pin Eggpack producer tooling

Select an exact reviewed Eggpack revision compatible with the repository's producer schemas.

Record it in:

```text
release/eggpack/github-policy.json
```

Generated CI installs Eggpack from that exact revision with `--locked`.

Pin GitHub Actions by commit SHA, including:

- checkout;
- Rust toolchain;
- upload/download artifact;
- any attestation action if supplementary provenance is enabled.

No floating `@main` or broad release tags in the release workflow.

## 3. Producer contract completeness

Finalize the M001 static files and add generated/runtime files only under ignored/generated locations where appropriate.

The source-controlled contract must define:

- product/release identity;
- exact two target triples;
- exact artifact names;
- build strategy/tool versions;
- glibc floor;
- native qualification;
- build binding to Cargo package/bin `wg-basic`;
- candidate smoke;
- installer presentation;
- GitHub draft policy.

Release contract drift tests compare committed producer inputs with the generated workflow shape.

## 4. Exact-tag/source preflight

Release workflow is manually triggered with an exact existing stable tag.

Before any target build:

1. checkout the exact tag;
2. resolve HEAD commit;
3. require tag `vX.Y.Z`;
4. require Cargo version `X.Y.Z`;
5. require `wg-basic --version` expected identity from that source;
6. require clean source/release contract;
7. capture exact source revision in Eggpack release plan.

A tag/version/source mismatch is terminal.

Do not retarget/move tags from this workflow.

## 5. Build lanes

Required target jobs:

### x86_64

- native x86_64 Linux runner;
- pinned Rust stable plus repository MSRV verification where useful;
- pinned cargo-zigbuild/Zig from producer policy;
- locked release build at declared glibc floor;
- capture canonical Eggpack build handoff.

### aarch64

- native aarch64 Linux runner;
- same policy;
- no compile-only closure.

Every build artifact is uploaded only through the pinned artifact action.

## 6. Qualification lanes

For each exact build handoff:

- verify source/release-plan continuity;
- run Eggpack core smoke;
- execute exact candidate `--version`;
- run product-owned release validator.

Product validator should include:

- `--help`;
- candidate target/ELF identity;
- glibc symbol-floor scan;
- read-only command smoke;
- architecture guard that no unsupported target was accidentally emitted.

Where a systemd/rootful target runner is available, deeper release qualification may reuse M002/M005 fixtures, but M003 does not need to duplicate M005's full install lifecycle.

## 7. ReleaseManifest production

The staging/finalization job gathers only qualified handoffs.

Generate:

```text
release-manifest.json
<binary>.sha256
install.sh
```

using Eggpack's resolved release identity.

Before draft creation, independently cross-check:

- manifest product ID;
- release ID/tag;
- source revision;
- target set exactly two;
- every manifest artifact name matches release contract;
- exact sizes match staged files;
- SHA-256 matches staged files.

No unqualified build may be included.

## 8. Bootstrap installer policy

Use Eggpack's bootstrap generator as the transport/integrity bootstrap.

Customize presentation/policy so generated `install.sh`:

- supports only Linux x86_64/aarch64;
- refuses unsupported host;
- downloads exact-version manifest/artifact URLs after version selection;
- uses HTTPS only;
- uses private staging;
- verifies SHA-256;
- does not perform its own hand-written service/unit mutation;
- delegates system installation to the candidate's M002 install surface;
- requires root for system mutation and does not call sudo itself.

If Eggpack's generated installer cannot cleanly delegate to a root product installer without violating its no-elevation/no-overwrite contract, stop and write a narrow Eggpack prerequisite rather than fork a large shell installer.

## 9. Installer authenticity handoff

Produce/sign:

```text
install.sh
install.sh.minisig
```

The generated script may embed the production public key for verifying the release manifest, but that does not make an unverified copy of the script self-authenticating.

Documentation must distinguish:

- convenience HTTPS bootstrap;
- high-assurance preverified installer.

Do not obscure this trust boundary.

## 10. Signing boundary

Normal GitHub Actions MUST NOT possess the production private signing key.

Staging sequence:

1. Eggpack stages a draft release with qualified unsigned manifest/artifacts/installer.
2. Workflow emits an immutable signing-request receipt:
   - repository;
   - draft release/tag;
   - source revision;
   - manifest SHA-256;
   - installer SHA-256;
   - artifact inventory/hashes.
3. Trusted maintainer environment downloads those exact bytes.
4. Maintainer verifies receipt/source bindings.
5. Maintainer signs exact manifest and installer with production Minisign key.
6. Signatures are uploaded to the same draft.
7. Release verification re-downloads the draft and verifies signatures/hashes.

Fixture CI may perform steps 3–7 using a fixture private key to qualify mechanics.

Never call fixture-signed output production-signed.

## 11. Optional GitHub/Sigstore attestations

M003 may add GitHub artifact attestations for the release binaries/manifest.

If added:

- treat as supplementary provenance;
- do not make updater depend on `gh` or online transparency logs;
- pin action/reusable workflow identity;
- document repository/workflow/source identity predicates.

Failure or absence of an optional provenance attestation must not cause the runtime verifier to bypass Minisign.

## 12. Draft-release ownership

Use Eggpack GitHub staging in draft mode.

Required safety:

- exact owner/repository;
- exact existing tag;
- no auto-publish;
- no tag creation/movement;
- source revision included;
- draft identity revalidated before signature upload;
- asset collision fails rather than overwrites foreign bytes unless Eggpack has an explicit owned-refresh contract proven here.

The first public publication remains a manual maintainer operation after M005/public-release readiness.

## 13. Consumer agreement fixture

Take the exact generated draft `release-manifest.json`.

Using wg-basic's M001 consumer code:

1. verify detached fixture/production signature as appropriate;
2. parse/project target via `eggup-eggpack`;
3. bind exact artifact URL;
4. acquire fixture artifact;
5. verify exact size/hash;
6. exact `--version` candidate check.

This proves producer and updater interpret the same manifest without duplicated hand-authored schema.

## 14. Release artifact reproducibility/determinism

Do not overclaim bit-reproducibility unless measured.

Record:

- exact compiler/tool versions;
- source revision;
- build target/floor;
- artifact SHA-256;
- qualification evidence.

If two same-input builds are byte-identical, record it as evidence but do not make deterministic bit-for-bit reproduction a closure prerequisite unless formally adopted.

Eggpack determinism here means deterministic contract/identity/staging, not necessarily compiler bit reproducibility.

## 15. Release security gates

Before a draft is considered qualified:

- ordinary Rust/MSRV CI green;
- cargo-audit gate green/dispositioned;
- Phase 6–9 rootful regressions green at tagged source;
- target builds/qualification green;
- source/tag/version binding green;
- producer/consumer agreement green;
- fixture signature negatives green;
- no unresolved high/medium release/security finding.

## 16. Test strategy

### Local/unit

- static release-contract validation;
- workflow drift;
- manifest inventory;
- signing-request receipt;
- exact source/version matching;
- consumer agreement.

### Hosted

- x86_64 producer build/qualify;
- aarch64 producer build/qualify;
- draft staging in a test/dry-run mode where possible;
- fixture detached-signature upload/verification without production key.

Avoid creating durable public releases in ordinary CI.

## 17. Acceptance criteria

M003 closes only when:

1. Eggpack is the canonical producer contract;
2. exact-tag/source/version binding is load-bearing;
3. both target artifacts are built and qualified from the tag;
4. generated manifest/checksums/install script agree with those exact bytes;
5. draft staging is deterministic and non-publishing;
6. signing-request receipt binds exact bytes;
7. fixture signing proves detached-signature handoff;
8. producer manifest is consumed successfully by the wg-basic verifier/Eggup adapter;
9. production private key is absent from repository/ordinary CI;
10. bootstrap trust documentation is accurate;
11. all prior CI remains green.

Production-signed-draft disposition must be stated explicitly:

- **complete** if maintainer production public/private-key provisioning was available and the exact draft was signed/verified;
- **mechanically qualified / production signing pending** if not.

The latter does not permit public release and may become an explicit prerequisite for M005 release readiness.

## 18. Stop conditions

Stop/write an Eggpack corrective if:

- current Eggpack cannot represent the two-target direct-artifact contract;
- generated bootstrap cannot delegate safely to product install;
- draft staging would move/create tags unexpectedly;
- consumer must reinterpret artifact names instead of using the manifest;
- signing requires placing production private material in ordinary CI;
- target qualification differs from the artifact actually staged.

## 19. Closure evidence

Record:

- Eggpack revision/action SHAs;
- exact producer inputs;
- generated workflow drift status;
- tag/source/version checks;
- target build/qualification receipts;
- manifest/checksum/install-script hashes;
- signing request/fixture signature verification;
- production-key/signed-draft disposition;
- producer/consumer agreement;
- dependency/advisory results;
- M004 readiness.

## 20. Blocker disposition (2026-10-08)

The original blocker was resolved upstream. Eggpack revision `d61ca71fc0112be63e7e8ba31ba8fa2b1ce5a628` adds the explicit `v_prefixed_stable_semver` mode. Its runtime identity envelope preserves the exact source tag, source revision, and unprefixed manifest `release_id`, with source/tag peel verification and stable-tag grammar validation. See `plans/closure/distribution/003-unblock-review.md`. The corrective is satisfied; M003 is active. The M001 verifier and `vX.Y.Z` source tag convention remain unchanged.
