# Release Readiness R004b — Signed-Production Gate Waiver

Status: **waived by maintainer decision** 2026-10-11. No production Minisign
trust root will be provisioned under this plan; wg-basic releases ship
**checksums-only** (GitHub TLS delivery + published SHA-256 digests, no
detached signatures). This record preserves what was waived, why the
remaining claims stay truthful, and what is lost.

## Decision

The maintainer directed removal of the signed-release gate so `v0.1.0`
could ship as a stable release without a signing ceremony. R004b's
key/draft/ceremony/signed-install requirements (§§4–10 of the R004 plan)
are waived as a body, not deferred: there is no pending key operation.

## What stays true

- `PRODUCTION_PUBLIC_KEY=None`; `update check` and `update run` fail
  closed before network access. No update path exists or is claimed, so no
  update path can be subverted. Every future release requires a fresh
  install until a trust root is ever provisioned.
- Release provenance is unchanged: frozen tag → source SHA, CI-built
  artifacts, staging receipt + run-bound provenance receipt, digest-bound
  manifest, byte-verified draft and public assets (see `004a-status.md`).
- The Minisign verifier, ceremony docs, and fixture negative matrix stay
  in the repo unmodified as the reference for a future trust root.
- No private key was generated, stored, or transmitted anywhere in this
  process; there is no key custody to audit because no key exists.

## What is lost (stated plainly)

- Release authenticity is GitHub-account security plus TLS. A compromised
  maintainer account, coerced hosting change, or TLS interception can ship
  malicious bytes that checksums cannot distinguish from legitimate ones.
- There is no cryptographic downgrade protection and no signed provenance
  chain from source to installed binary.
- The high-assurance installer path in `docs/installation.md` is
  checksums-and-manifest-consistency only; it cannot authenticate the
  publisher.

## Promotion performed

- `v0.1.0` release notes rewritten to stable checksums-only wording
  (unsigned disclosure retained, digest matrix retained, pre-release
  limitations lifted except the permanent checksums-only ones).
- Release flipped from pre-release to stable (`isPrerelease: false`);
  assets unchanged (same 9 files, same bytes, same digests).
- Operator docs (`installation.md`, `release-signing.md`,
  `operations-runbook.md`, `development.md`, `README.md`,
  `release/trust/README.md`, `architecture/update-rollback-contract.md`)
  updated to the checksums-only policy in the same change.

## Reversal

Reinstating signed releases requires a new plan (new trust root,
ceremony, signed draft, installer re-qualification); this waiver does not
pre-authorize it, and the ceremony docs must be re-reviewed before reuse.
The R004 plan §§4–10 remain the specification for that future work.
