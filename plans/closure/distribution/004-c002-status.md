# Distribution M004 C002 — Rootful Transaction Qualification and Operator Contract

Disposition: **closed**.

Date: 2026-10-09

## Baseline and implementation revision

- C002 baseline: `79e2a90` (C001 strict closure and C002 handoff).
- Qualified implementation head: `0b01078df0d554b7d0b7c05ea90d283afe7f79f6`.
- C002 corrective commits include the rootful fixture and documentation work
  preceding the final updater recovery corrections at `8dffe49` through
  `0b01078`.
- C001 strict evidence remains in
  `plans/closure/distribution/004-c001-status.md`; scoped C001a evidence remains
  in `plans/closure/distribution/004-c001a-status.md`.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Signed update on an installed system with real systemd services | The disposable Ubuntu 24.04 rootful test installs a release-mode schema-v4 fixture, provisions exact owned units, creates enabled and intentionally disabled product profiles, signs a strictly newer schema-v5 candidate with a test-only key, and executes the production update transaction. | Passed in dedicated rootful CI run `37929914324`. |
| Candidate timeout, migration/health failure, rollback ordering, identity, and traffic | The test forces the candidate's bounded service-start timeout, candidate netd failure, and post-migration health failure. It checks compatible state restoration before old services return, exact old InstallationId/schema/generation/product identity, old unit ownership, and renewed client handshake/traffic. | Passed; old product health and real traffic resumed after each rollback. |
| Updater SIGKILL and repeat recovery | The test externally observes durable journal phases and interrupts the updater at prepared/backup/service-stop/binary-commit/candidate-start/health/rollback windows; `update recover` is repeated twice at each applicable cutpoint. A scratch-patched v4 binary pauses inside the actual restore replacement after the old database is durably moved aside; the updater process group is killed and recovery completes twice. | Passed; final schema-v4 identity and traffic were restored. |
| Failed-unit and transitioning-service recovery | Exact-owned service stop uses the published Eggup 0.1.3 typed lifecycle/stop contract. A transitioning start is cancelled for the exact unit, then re-inspected; Eggup's quiescence proof is retained through the final ownership/postcondition check. | Passed in the signed rootful rollback and retry flow; no generic process execution or kill path was added. |
| Foreign/tampered resource refusal and retry | The rootful matrix corrupts or replaces journal, metadata, backup, binary, and owned unit inputs; removes the serve lease; injects netd/start failure; and retries after rollback. Refusals retain evidence and do not start an incompatible old binary. | Passed; final signed retry reached Committed. |
| Both health profiles and release artifacts | Enabled WireGuard server/client traffic and intentionally disabled-but-healthy product profiles are both exercised. Current-head native release workflow builds and executes x86_64 and aarch64 GNU artifacts at the declared glibc floor; release-contract and generated-workflow drift checks pass. | Passed in runs `37929914324` and `37929920418`. |
| CLI, docs, footprint and transport contract | Operator contract remains `update check`, `update run`, and `update recover`; root requirements, fail-closed production trust-root state, recovery refusal behavior, transport comparison, readiness/footprint/storage receipts, and M005 handoff are recorded in current docs and the C002 plan. | Reconciled; production signing/publication remains explicitly pending. |

## Exact verification evidence

All workflow runs below used head
`0b01078df0d554b7d0b7c05ea90d283afe7f79f6`:

- [Dedicated rootful updater run 37929914324](https://github.com/dbowm91/wg-basic/actions/runs/37929914324), job [update-transaction-rootful](https://github.com/dbowm91/wg-basic/actions/runs/37929914324/job/113817825546): `1 passed; 0 failed`, 257.57 seconds. Environment: Ubuntu 24.04, x86_64, kernel `6.17.0-1022-azure`, systemd `255.4-1ubuntu8.17`.
- [Full CI run 37929917248](https://github.com/dbowm91/wg-basic/actions/runs/37929917248): all 15 jobs passed, including rootful updater, Phase 6–9 network/product/maintenance/update rehearsals, Rust 1.89 format/check/clippy/tests, and cargo-audit.
- [Distribution foundation run 37929920418](https://github.com/dbowm91/wg-basic/actions/runs/37929920418): release-contract plus native x86_64 and aarch64 GNU build-and-execute jobs all passed.
- Local development gates on the production implementation: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (564 passed, 3 ignored, 36 suites), and `cargo +1.89.0 check --all-targets --locked` passed. Rootful suites were not run on the shared development host.

The dedicated fixture receipt records old fixture v0.1.0 (`x86_64-unknown-
linux-gnu`, 11,233,216 bytes, SHA-256
`813c17bffffade8ef982381a1567ac7ab3d8a074272004281f0e8313da65c382`), signed
candidate v0.1.1 (12,643,600 bytes, SHA-256
`2b4500117763f79e73e0952b1869f4dc3a5c0035936f33c678abb26ee8be79e2`), and
signed manifest (370 bytes, SHA-256
`df8c834873e355916b68e0a63ec93607166de3666590839cad9382ff7272c386`). The
test-only signing key is never linked into a normal release artifact.

Observed update storage receipts include a 212,992-byte consistent state
backup, 11,233,216-byte old executable, 12,643,600-byte candidate, 1,105-byte
install receipt, and 980–984-byte journal. Peak recovery evidence included a
same-size runtime old-binary copy; after final rollback/recovery cleanup the
runtime copy returned to zero while the retained transaction backup remained
available.

## Security, ownership, documentation, and limitations

The update implementation changes only exact owned files, journal metadata,
and exact owned systemd services. State backups and restore staging remain
private and secret-bearing. The scratch old-v4 restore gate exists only in the
disposable fixture source; no production crash switch or signature bypass was
introduced. No unresolved high or medium distribution/security finding was
observed in the scoped qualification.

The production Minisign trust root has not been provisioned. Production
`update check` and `update run` correctly fail closed before network access;
fixture proof establishes transaction mechanics, not production signing or
release authorization. This external readiness condition remains blocked and
is not a blocker for technical M004 closure or M005 implementation.

## Successor status

C002 closes the final M004 technical qualification gap. Together with C001 and
C001a, the M004 acceptance contract is satisfied. The canonical M004 record is
`plans/closure/distribution/004-status.md`. M005's hard dependency is closed,
so its implementation plan is now ready. Public production signing and
publication remain pending maintainer action.
