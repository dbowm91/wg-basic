# Distribution M003 Closure — Eggpack Pipeline and Signed Draft Handoff

Status: **blocked** (corrective prerequisite identified)

Source plan: `plans/implementation/distribution/003-eggpack-release-pipeline-and-signed-draft.md`

Roadmap: `plans/subsystems/distribution-install-update-roadmap.md`

Repository baseline: M002 closure at `d1813da` (M003 activation recorded at `d140be9`).

Final inspected implementation baseline: `d140be9` (no M003 product changes). The blocked disposition and this record were committed and pushed after that baseline.

## Requirement-to-evidence matrix

| Requirement | Evidence reviewed | Result |
|---|---|---|
| Eggpack producer and M001 consumer agree on release identity | Pinned Eggpack `e5c81f28bd328d4aea41c3f061a0ed9944306262`; adjacent clean checkout `3ef806fedc9d7683948e5678ec0d3c7b78c06f0e`; resolver uses exact tag as release ID, while M001 requires unprefixed stable SemVer. | **Blocked**; manifest consumer agreement is impossible under current contract. |
| Exact tag/source/version preflight and target production | No workflow or target build retained; contract mismatch occurs before implementation qualification. | Not run. |
| Generated manifest, installer, draft staging, signing receipt, fixture signature handoff | No qualified generated output or staging run. | Not run. |
| Producer-consumer agreement fixture | Required M001 consumer rejects the producer's `vX.Y.Z` identity. | Failed at contract review; no artifact fixture claimed. |
| Production signing boundary | No signing material used or placed in CI. | Not exercised; M001 trust root remains provisioning-required. |
| Existing codebase status | No product code changes. Exploratory policy/workflow-shape edits were discarded. | M001/M002 implementation remains untouched. |

## Blocker and corrective disposition

Eggpack treats the exact Git tag as opaque `release_id`; the consumer treats manifest `release_id` as a stable semantic version without the tag prefix. Changing only workflow code to strip the prefix would reinterpret Eggpack's plan and leave the producer/source/tag binding unproven. M001 consumer behavior and M003's exact `vX.Y.Z` tag requirement remain unchanged.

The corrective prerequisite is `plans/implementation/distribution/003-eggpack-identity-seam-corrective.md`: Eggpack must carry exact source tag/revision separately from product manifest release ID and bind both through build, finalization, manifest, and draft staging. M003 has not met its acceptance criteria and is not closed.

## Verification actually performed

- Inspected the pinned Eggpack resolver, CLI documentation, and tests in the adjacent checkout.
- Inspected current adjacent Eggpack revision `3ef806fedc9d7683948e5678ec0d3c7b78c06f0e`; checkout was clean.
- Built the pinned Eggpack CLI with `cargo +1.89.0 build --manifest-path /tmp/wg-basic-eggpack/Cargo.toml -p eggpack-cli --release --locked` during exploration. This does not qualify M003.
- No Rust product tests, target build, release workflow, staging, or signature verification was run for M003.

## Dependencies and handoff

M004 remains blocked on strict M003 closure. M005 remains blocked on strict M004 closure. No other Phase 10 plan is eligible. Production-signed release readiness also remains gated on maintainer provisioning of the production trust root.

Disposition: **blocked**. Do not treat this record as M003 closure or as authorization for public release.
