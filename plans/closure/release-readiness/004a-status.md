# Release Readiness R004a — Initial Unsigned Pre-release Closure

Status: **closed** 2026-10-11. `v0.1.0` is a public GitHub pre-release
(evaluation only, unsigned). This record claims checksums and provenance
only; no authenticity beyond SHA-256 binding is claimed. R004b production
signing remains blocked on maintainer key provisioning.

## Candidate identity

- Tag `v0.1.0` (annotated object `70728390ce0b90ef8c8f992ec8926d415358eec3`)
  peels to source `7527241f94ddf9f315297339d789e057f127d086`.
- Cargo `0.1.0`, manifest `release_id` `0.1.0`, binary `--version`
  `wg-basic 0.1.0`: identity agrees across tag/manifest/Cargo/binary.
- Candidate diff vs last qualified head is plans/docs-only; `cargo audit`
  clean (211 crates, 0 vulnerabilities); `main` CI green at `2c5019f`
  (CI `38115169323`, Distribution Foundation `38115169341`).

## Release run and receipts

- `release-eggpack.yml` dispatch with `release_tag=v0.1.0` from fixed
  `main`: run `38115877717` completed success, all 11 jobs
  (preflight, resolve, 2× build, 2× qualify, 2× validate, gate,
  aggregate, stage). First dispatch (run `38112750263`) failed closed in
  `resolve` (RF-07); producer fix `eggstack/eggpack@a0fec98` verified live
  by this run's green `resolve`.
- Provenance receipt run `38152418203` completed success.
- Staging receipt: tag `v0.1.0`, source `7527241…`, 9 assets,
  `draft: true`, GitHub release id `409758640`.
- `scripts/verify-release-signing-bundle.py` exit 0: source/run/tag/draft
  identity, live inventory, and fresh-download byte equality verified;
  Cargo version agreement verified. Zero `.minisig` assets present, so no
  signature was verified — the unsigned state is the recorded outcome,
  not a gap.

## Digest matrix (draft download == public download == manifest)

| Asset | SHA-256 | Size |
|---|---|---|
| `wg-basic-x86_64-unknown-linux-gnu` | `b817bd9a536f51306b39c59aec5f7c4ac754b7c52904c70db8d9abf1eb4ff4b0` | 9,566,792 |
| `wg-basic-aarch64-unknown-linux-gnu` | `5127365a0335c620331c417d126b9c49320c1de5efccdec2e4571232f3476227` | 8,821,200 |
| `install-exact.sh` | `57b14a65ec7e28bc65ce32c0267383a88cee54be162f50a03c4f53b9344b6c47` | 3,014 |
| `install.sh` | `7ff8f4f8bf71ef839035d0e0645d591cf989b606fa6224ec3148f7217afacc0d` | 4,625 |

Sidecar `.sha256` files match; installer digests match the GitHub API
digests; public files (downloaded via public URLs after API quota
exhaustion) are byte-identical to the verified draft downloads; public
x86_64 binary executes and reports `wg-basic 0.1.0`.

## Approvals and publication

- Staging approval: maintainer, via `release-staging` environment on run
  `38115877717` (creates draft only; reversible).
- Release notes: unsigned evaluation-only wording with the digest matrix,
  installer guidance (candidate vs LOWER-ASSURANCE convenience mode),
  requirements, and limitations (no auto-update — fresh install required;
  hosted-CI install qualification only; no disclosure contact yet).
- Publish: maintainer flipped draft → public pre-release
  (`isDraft: false`, `isPrerelease: true`, published `2026-10-11T15:50:29Z`).
- Public re-verification: this record, from public-URL downloads.

## Known limitations (carried to R004b, not defects)

- No Minisign signatures; updater fail-closed (`PRODUCTION_PUBLIC_KEY=None`).
- Install evidence is hosted CI systemd lifecycle, not a bare-metal run.
- No full WP2 review (candidate is plans-only vs qualified heads).
- No published security disclosure contact.
- `v0.1.0` tag predates the RF-07 workflow fix on `main`; the release
  workflow ran from fixed `main` against the frozen tag source, so the
  shipped bytes are unaffected.

Neither this closure nor its evidence authorizes production signing or a
stable release. R004b proceeds under §§4–10 of the R004 plan when the
maintainer provisions a release trust root.
