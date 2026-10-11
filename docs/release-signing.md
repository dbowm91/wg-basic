# Release signing and trust-root operation

This document describes the release signing boundary and the retained
signing ceremony reference. It is not evidence that production signing has
occurred. By maintainer decision (2026-10-11, waiver
`plans/closure/release-readiness/004b-waiver-status.md`) releases are
checksums-only: no production Minisign key is provisioned and none is
planned. Fixture keys under `tests/fixtures/release-auth/` are test-only.

## Trust and custody (reference — no key exists)

If a production key is ever provisioned under a new plan, the private key
belongs to an explicitly authorized maintainer and stays on a segregated
signing host. It must not enter this repository, ordinary CI, an
artifact store, a container, or a command log. Keep an encrypted offline backup
under separate custody. Record the public key ID/fingerprint and its independent
distribution channel here only after a maintainer has authenticated them.

There is no production fingerprint in this document yet. Never treat a public
key fetched from the same GitHub release page as an independent trust anchor.
Before using the production key, compare the complete canonical Minisign public
key and fingerprint with the separately published project trust record. Key
rotation requires a reviewed trust transition anchored by the old key or an
explicit out-of-band reinstall. If the private key is lost or suspected
compromised, stop signing and publication; do not replace the key silently.

## Verify a draft before publication

The release workflow emits an `eggpack-staging-receipt` artifact. When that
workflow succeeds, `.github/workflows/release-provenance.yml` downloads only
that artifact from the completed run and emits a separate
`release-provenance-<run-id>-<attempt>` artifact. The second workflow has
read-only `actions` and `contents` permissions. Its JSON binds the release
receipt to both GitHub run IDs, attempts, workflow SHAs, tag, source revision,
and asset inventory. The JSON is a locator and consistency receipt; GitHub's
run records, protected repository policy, and live draft remain the authority.

From an independently reviewed checkout at the tagged source revision, obtain
both artifacts and all draft assets afresh. Confirm in GitHub that:

1. the source `Eggpack candidate builds` run completed successfully, was a
   `workflow_dispatch`, and is the recorded run/attempt/workflow SHA;
2. the `Release provenance receipt` run completed successfully and is the
   recorded provenance run/attempt/workflow SHA;
3. both workflows are the reviewed workflow revisions and their artifacts were
   downloaded from those exact run IDs;
4. the live draft tag still resolves to the recorded source commit and no
   unexpected asset exists;
5. the release candidate, native target gates, aggregate gate, and current CI
   evidence correspond to the intended source revision.

Then run the preflight. It queries GitHub through the authenticated `gh` CLI,
resolves the tag independently, downloads the live draft again, compares every
byte with the local copy, validates manifest/sidecar/receipt consistency, and
verifies any signatures present (none exist under the checksums-only policy;
the tool skips signature verification when no `.minisig` assets are staged):

```sh
python3 scripts/verify-release-signing-bundle.py \
  ./eggpack-staging-receipt.json \
  ./release-provenance.json \
  ./draft-assets \
  --public-key /etc/wg-basic/release.pub
```

The tool requires `gh`, `git`, and `minisign` (only needed if signatures
are present). Its checks supplement the
independent human review above; it does not authenticate repository protection
settings or CI actors. Do not publish if either run, tag, source revision, asset
inventory, or current draft differs from the reviewed packet.

## Offline signing ceremony (reference — not current practice)

No signing key exists and none is planned, so this ceremony is retained
reference for a future trust root under a new plan. Do not provision a key
by following this section alone; it requires plan authorization first.

Transfer the exact preflighted `release-manifest.json` and `install.sh` bytes to
the signing host over an authenticated channel. Review the version, source
commit, supported target set, target sizes and hashes, workflow run IDs, CI
results, and expected filenames. Sign the two files separately:

```sh
minisign -S -s /secure/offline/wg-basic.key \
  -m ./draft-assets/release-manifest.json \
  -x ./draft-assets/release-manifest.json.minisig
minisign -S -s /secure/offline/wg-basic.key \
  -m ./draft-assets/install.sh \
  -x ./draft-assets/install.sh.minisig
minisign -V -p /etc/wg-basic/release.pub \
  -m ./draft-assets/release-manifest.json \
  -x ./draft-assets/release-manifest.json.minisig
minisign -V -p /etc/wg-basic/release.pub \
  -m ./draft-assets/install.sh \
  -x ./draft-assets/install.sh.minisig
```

Have the designated reviewer verify the detached signatures and public-key
fingerprint. The maintainer may serve as the sole reviewer. Upload only the
two signature files to the same draft through the
maintainer-controlled GitHub interface. Re-download the complete draft and run
the preflight again; the verifier checks the live bytes and both signatures.
Record the run URLs, source/tag identity, public fingerprint, asset hashes,
reviewer, and approval in the non-secret release packet. No second reviewer is
required. Never record private
key material or use the private key in Actions.

Staging approval does not authorize publication. Only the explicit maintainer
decision can authorize changing a verified draft to public. After an authorized
publication, download every public asset again and repeat identity,
target, and hash verification.

## Repository settings release gate

Read-only inspection on 2026-10-10 found no repository rulesets, no branch
protection on `main` (the GitHub endpoint returned `404 Branch not protected`),
and no tag protection rules. Actions are enabled for all actions, while the
repository's default `GITHUB_TOKEN` permission is read-only. The generated
release workflow pins each action by full commit SHA and grants `contents: write`
only to its gated `stage` job. These observations are not repository policy
changes.

Before any public release, a repository maintainer must configure and verify:

- a `main` branch ruleset requiring the required CI/release-contract status
  checks, with no required pull-request approvals. This is a
  solo-maintainer project: the maintainer merges their own PR after green
  checks. No second reviewer is required by project policy;
- an immutable `v*` tag ruleset with tag creation restricted to authorized
  release maintainers;
- a release-staging Environment with one required reviewer. The repository
  maintainer is the sole reviewer; GitHub permits that reviewer to approve a
  deployment they initiated. No second reviewer is required by project policy;
- the minimum GitHub Actions allowlist and read-only default token permission.

Use these read-only API calls to repeat the settings review and retain their
JSON in the release packet:

```sh
gh api repos/dbowm91/wg-basic/rulesets
gh api repos/dbowm91/wg-basic/branches/main/protection
gh api repos/dbowm91/wg-basic/tags/protection
gh api repos/dbowm91/wg-basic/actions/permissions
gh api repos/dbowm91/wg-basic/actions/permissions/workflow
```

The generated `stage` job now uses the `release-staging` Environment supported
by Eggpack M003k. GitHub configures the sole required reviewer as `dbowm91`
with self-review allowed. The `main` ruleset requires no approving
pull-request review, so the maintainer merges their own PR once required
checks are green; no other account is needed. Releases ship checksums-only
by maintainer decision; no authorized key or signed draft exists or is
planned — exact release qualification and the maintainer go decision remain
required for every publication.
