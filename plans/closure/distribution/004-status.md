# Distribution M004 — Transactional Self-Update and Rollback

Disposition: **closed** (technical implementation and qualification; production
signing/publication remains externally blocked).

Date: 2026-10-09

## Implementation revision

- M004 began from the closed M003 producer handoff and C001 corrective
  baseline; C001 implementation head: `e26e9f2396dcd0719667e6b7bc906fde96269f3c`.
- C001 closure/handoff: `79e2a90`; C001a scoped closure:
  `540c98ce7790ffb14cb82c98ec5167854555972b`.
- Final M004 qualified implementation head:
  `0b01078df0d554b7d0b7c05ea90d283afe7f79f6`.
- C001, C001a, and C002 evidence is recorded in
  `plans/closure/distribution/004-c001-status.md`,
  `plans/closure/distribution/004-c001a-status.md`, and
  `plans/closure/distribution/004-c002-status.md` respectively.

## Requirement-to-evidence matrix

| M004 requirement | Evidence | Result |
|---|---|---|
| Signed metadata and exact target artifact selection; no source/Cargo fallback | Release verification binds manifest signature, version, target, artifact name, size, and digest. Fixture signing traverses the production parser/projection and acquisition transaction through a test-only injection seam. Release-contract tests ensure production trust-root absence remains fail-closed. | Passed. |
| Eggup transaction, root-owned durable journal, and binary+database recovery contract | Eggup 0.1.3 owns staged binary replacement and typed systemd actions. wg-basic owns its exact service ordering, transaction journal, install receipt, compatible SQLite backup/restore, product health, and durable commit decision. | Passed in C001/C001a/C002 rootful evidence. |
| Services stop before snapshot/replacement; compatible DB restore precedes old service start | Real two-service systemd runs prove lease/socket quiescence, migration, post-commit candidate failure, old-compatible database restore, old binary restoration, old health, and real traffic recovery. Transitioning/failed unit cases preserve Eggup proof and exact ownership checks. | Passed in `37929914324`. |
| Candidate health precedes durable commit and successful update preserves identity/traffic | Signed v4→v5 candidate reaches candidate health and commit, preserves product identity, and supports fresh traffic on the same client configuration. Final retry after rollback commits successfully. | Passed in `37929914324`. |
| Retry and representative process-kill recovery, including interrupted restore | C001/C001a phase and adversarial matrix plus C002 real updater SIGKILL and repeated recovery. The v4 fixture is paused after its old target has been durably retained and before staging installation, then killed; recovery proves the compatible pair and traffic. | Passed in `37929914324`; prior C001 evidence is retained unchanged. |
| Read-only check, safe refusal, and production trust behavior | CLI remains `update check`, `update run`, and `update recover`; check is non-mutating, mutation/recovery require effective root, and production check/run fail closed before network without the maintainer key. | Passed by release/unit/rootful checks; key provisioning remains external. |
| Existing phases, supported target builds, Rust MSRV, and security gates | Full current-head CI and distribution foundation workflow pass all existing installation, upgrade, kernel/network, product, durability, maintenance, Rust, audit, release-contract, and native x86_64/aarch64 jobs. | Passed in `37929917248` and `37929920418`. |

## Verification

All final hosted evidence used head
`0b01078df0d554b7d0b7c05ea90d283afe7f79f6`:

- Full CI: [run 37929917248](https://github.com/dbowm91/wg-basic/actions/runs/37929917248), all 15 jobs successful.
- Dedicated signed updater systemd qualification: [run 37929914324](https://github.com/dbowm91/wg-basic/actions/runs/37929914324), job [113817825546](https://github.com/dbowm91/wg-basic/actions/runs/37929914324/job/113817825546), 1 passed in 257.57 seconds on Ubuntu 24.04, x86_64, kernel `6.17.0-1022-azure`, systemd `255.4-1ubuntu8.17`.
- Release contract and native GNU target qualification: [run 37929920418](https://github.com/dbowm91/wg-basic/actions/runs/37929920418), all three jobs successful.
- Local Rust gates: format check, all-target locked check, all-target clippy with warnings denied, full test suite (564 passed, 3 ignored), and Rust 1.89.0 locked all-target check passed. Rootful qualification ran only on disposable hosted runners.

## Security, operational limits, and release disposition

Journal schema compatibility, binary/database pairing, exact service ownership,
state identity, lease/socket postconditions, refusal artifact retention, and
secret redaction remain enforced. No generic command execution, arbitrary
privileged IPC, process killing, production signature bypass, or trust-root
fallback was added.

M004 is technically closed because signed-fixture qualification proves the
transaction contract and the implementation correctly fails closed without a
production key. The maintainer-provisioned Minisign public key, production
signed draft, release authorization, and actual publication remain pending.
Therefore no public release or production update readiness is claimed. These
operational items do not block M005's technical lifecycle work; M005 must keep
the release-readiness gate explicit.

## Successor

M005 is unblocked and ready. It owns fresh install, signed update lifecycle,
uninstall/reinstall state preservation, explicit purge, exact release artifact
qualification, and Phase 10 closure. Its status is tracked in
`plans/implementation/distribution/005-install-update-uninstall-e2e-and-phase10-closure.md`.
