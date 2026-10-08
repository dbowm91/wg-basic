# Distribution M003 Corrective — Separate Manifest Identity from Git Tag

Status: prerequisite specification; implementation belongs to Eggpack

Source plan and blocked closure:

- `plans/implementation/distribution/003-eggpack-release-pipeline-and-signed-draft.md`
- `plans/closure/distribution/003-status.md`

## Finding

The currently pinned Eggpack producer resolves the exact Git tag as its `release_id`. For the required stable tag `vX.Y.Z`, this produces a manifest ID rejected by the already-closed M001 consumer, which requires stable SemVer `X.Y.Z`. Workflow-side rewriting would make wg-basic reinterpret Eggpack's resolved plan and would not prove that the generated artifacts, manifest, and draft release share one identity.

## Required Eggpack contract

Eggpack must represent and validate two linked values:

- the exact immutable source tag (for example `v1.2.3`) and resolved source revision;
- the product manifest release ID (for example `1.2.3`).

The producer must bind both values through plan resolution, build handoffs, finalization, manifest production, signing-request receipt, and GitHub draft staging. It must reject a tag/version mismatch and must not create or move a tag. Product policy must explicitly declare the mapping; no implicit generic stripping or normalization is acceptable.

## Required upstream implementation and evidence

1. Add a schema/CLI representation for both identities and validate the product policy mapping.
2. Update runtime planning and build/finalization handoffs so every receipt carries the source tag, source revision, and manifest release ID.
3. Ensure generated manifests and artifact naming use the manifest release ID while GitHub draft operations remain bound to the exact source tag.
4. Add tests for stable tags, mismatches, tampering between handoff stages, and exact draft tag preservation.
5. Publish an exact reviewed Eggpack revision and locked dependency/action pins.
6. In wg-basic, regenerate and validate the workflow from that revision; prove the exact producer manifest passes M001 verification/Eggup projection without consumer changes.

## Unblock criteria

M003 may resume only after the upstream interface and its evidence are available at an immutable revision. Re-review the M003 plan and update its pinned producer revision. M004 and M005 remain blocked until their declared predecessor closes. This corrective does not authorize changing the M001 consumer contract, tag convention, or production signing boundary.
