# Release Readiness R002 — Non-secret Conditional Closure

Disposition: **conditionally closed for non-secret tooling; production signing blocked**.
Implementation commit: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Repository baseline: `0b814fe` (`2026-10-10`).
Repository implementation head: `bd7c085d191ccf147e0f4dab72fde7cc8818f3fd`.
Source plan: `plans/implementation/release-readiness/002-production-trust-root-and-offline-signing-ceremony.md`.
Roadmap: `plans/subsystems/release-readiness-security-roadmap.md`.

## Evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Bind staging receipt to Actions identity | `release-provenance.yml` creates a read-only provenance artifact with source run/attempt/workflow SHA and receipt-producing run identity | Implemented; no real release staging run yet |
| Validate run, tag, and live draft | `scripts/verify-release-signing-bundle.py` checks both GH run records, current tag OID, live draft inventory, fresh asset downloads, source checkout, and Cargo release version | Implemented; API path not exercised against an actual draft |
| Verify exact staged bytes | Existing `verify-signing-request.py`, called on freshly downloaded live assets | Fixture identity/tamper controls pass |
| Detached signature validation | Bundle verifier invokes Minisign for both manifest and installer signatures when present; Rust signing-handoff test uses ephemeral keys and checks wrong-key/tamper/truncated cases | Hosted test suite passed |
| Keep key fail-closed | `src/release.rs::PRODUCTION_PUBLIC_KEY` remains `None`; no production key, placeholder, or signing secret was created | Pass; production operations blocked |
| Offline ceremony, rotation, incident and re-download procedure | `docs/release-signing.md` | Implemented; no key custody record exists |

## Exact verification run

- Local `python3 scripts/test-release-signing-bundle.py`: passed run-conclusion
  and moved-tag rejection controls.
- Local `python3 scripts/test-release-provenance.py`: passed source and
  provenance run binding checks.
- Local `python3 scripts/test-signing-request.py`: passed valid inventory and
  tampered-asset rejection.
- Hosted [CI run 38022851605](https://github.com/dbowm91/wg-basic/actions/runs/38022851605): all jobs passed at the implementation SHA; this includes `rust` and `dependency-audit`.
- Hosted [Distribution Foundation run 38022853831](https://github.com/dbowm91/wg-basic/actions/runs/38022853831): release-contract and native artifact lanes passed.
- Local `cargo audit`: passed.
- No production `minisign` private key was generated, copied, logged, or uploaded.

## Trust-chain limits and blocked operations

The JSON provenance records are not signatures. The maintainer must download
the provenance artifact from its exact workflow run, inspect both run records,
review workflow sources and repository protections, and independently approve
the release source/tag/asset set. The signing-bundle CLI uses authenticated
`gh`, current GitHub tag/release data, and local `minisign`; no live draft was
available to run that full command.

No project public key/fingerprint or out-of-band custody confirmation exists.
No detached production signatures, embedded trust root, signed draft, or
publication authorization exist. These require maintainer-controlled key
custody and a qualified R001 source/draft handoff; no agent action can
substitute fixture evidence for them. Do not update `src/release.rs` with a
placeholder key.

## Findings and handoff

- RF-02 source/run/asset authenticity: tooling implemented, live production
  chain not exercised (High release gate).
- RF-03 production trust root: intentionally absent (absolute release blocker).
- Key rotation/revocation and two-person signer approval are documented
  policy, not operationally attested.

R003 can use the documented detached-signature procedure once the maintainer
publishes an independently authenticated key and signed draft. R004 remains
blocked until actual key custody, signatures, exact current-SHA evidence, and
maintainer approval are supplied.
