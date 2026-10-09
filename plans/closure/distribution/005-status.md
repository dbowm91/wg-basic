# Distribution M005 — Install/Update/Uninstall E2E and Phase 10 Closure

Disposition: **closed — release-mechanically complete, public publication blocked**.

Date: 2026-10-09

## Implementation revision

- Final qualified implementation head: `c7de919c0b9d8f3326c50c799779ee5dc3734dca`.
- Lifecycle implementation was introduced at `dd048f0`; native footprint,
  systemd assertion, and hosted artifact-mode corrections followed through
  `8de10f2`. The final updater-fixture correction is `c7de919`.
- M004 technical closure and its corrective evidence remain unchanged at
  `plans/closure/distribution/004-status.md` and the linked C001/C001a/C002
  records.

## Requirement-to-evidence matrix

| M005 requirement | Evidence | Result |
|---|---|---|
| Exact supported x86_64 and aarch64 GNU release candidates | The distribution workflow built both artifacts at the declared glibc 2.17 floor, smoke-tested each on its native runner, recorded target size/digest, and uploaded the exact binaries consumed by the lifecycle jobs. | Passed. |
| Fresh native systemd install and product service contract | The rootful system-install fixture installs the supplied release binary on a clean systemd host, starts real `netd` and `serve`, checks systemd properties/capabilities and ownership, and exercises health and management. Both native architectures passed. | Passed. |
| Modified/foreign installation refusal | The lifecycle fixture changes owned executable/unit/sysusers/receipt material and proves uninstall refuses without deleting or overwriting it; the executable mutation is performed with services stopped to respect Linux executable mapping rules. | Passed on both native architectures. |
| Default uninstall preserves secrets and identities; reinstall reuses state | The fixture uninstalls the owned program while retaining the state DB and `wg-basic` identities, reinstalls the exact native artifact, verifies database identity, and re-establishes product health. | Passed on both native architectures. |
| Explicit disable, guarded purge, and post-purge uninstall | The actual signed-update fixture disables and converges the VPN, invokes purge with the exact installation ID, confirms the canonical DB is absent, then removes the remaining owned installation. The purge commands use the installed schema-v5 candidate after migration. | Passed in the full rootful updater run. |
| Signed update, post-migration rollback, interrupted recovery, retry, and traffic | The existing actual-updater fixture exercises the signed schema-v4-to-v5 candidate, real systemd services and WireGuard traffic, forced candidate failure, compatible DB/binary rollback, recovery after representative process kills, successful retry, identity preservation, and post-retry traffic. Its post-reinstall cleanup regression was corrected so the schema-v5 candidate performs state operations. | Passed. |
| Production signing/publication boundary | Fixture signing validates mechanics only. Production `check`/`run` remain fail-closed with no provisioned trust root; no public release was published. | Correctly blocked pending maintainer key, signed draft, and explicit publication action. |
| Security and regression gates | Exact M005 source diff received a Codex Security diff review with zero findings. Full current-head CI passed Rust formatting/check/clippy/tests, Rust 1.89, dependency audit, all Phase 6–9 rootful/kernel/upgrade lanes, and update transaction qualification. | Passed; no unresolved high/medium distribution finding. |

## Native artifact and host receipts

The exact final-head artifacts were tested on native Ubuntu 24.04 runners,
kernel `6.17.0-1022-azure`, systemd `255.4-1ubuntu8.17`:

| Target | Binary bytes | SHA-256 | Installed product bytes | Idle serve/netd RSS | Fresh install |
|---|---:|---|---:|---:|---:|
| `x86_64-unknown-linux-gnu` | 9,934,872 | `2ba82f7da2e7116259420985dae7b831cf1d8ddc68fd2322a1e47c98e44de920` | 9,937,817 | 9,192 / 6,556 KiB | 2,387 ms |
| `aarch64-unknown-linux-gnu` | 9,093,552 | `19d1ec1aaba5b0abdde20e3290e72681ea9e3f7d7309d25e395f95a79c4ad96c` | 9,096,498 | 8,068 / 5,560 KiB | 5,195 ms |

Dynamic dependencies on both targets are the system `libm`, `libpthread`,
`libc`, `libdl`, and the ELF loader. These one-run install/RSS receipts are
engineering measurements, not service-level objectives. The updater fixture
also recorded transient storage use for live/WAL state, compatible backup, old
and candidate binaries, install metadata, journal, and retained old binary.

## Verification

All final evidence is for head
`c7de919c0b9d8f3326c50c799779ee5dc3734dca`:

- Full CI: [run 37936112512](https://github.com/dbowm91/wg-basic/actions/runs/37936112512), all 15 jobs successful. The updater rootful test passed 1 test in 264.15 seconds on Ubuntu 24.04 x86_64, kernel `6.17.0-1022-azure`, systemd `255.4-1ubuntu8.17`.
- Release contract, native artifacts, and systemd lifecycle matrix: [run 37936276064](https://github.com/dbowm91/wg-basic/actions/runs/37936276064), all five jobs successful.
- x86_64 lifecycle job [113840199783](https://github.com/dbowm91/wg-basic/actions/runs/37936276064/job/113840199783): 1 passed in 13.78 seconds.
- aarch64 lifecycle job [113840199711](https://github.com/dbowm91/wg-basic/actions/runs/37936276064/job/113840199711): 1 passed in 20.32 seconds.
- Local checks for the final updater-fixture adjustment: `cargo fmt --all -- --check`, `cargo test --locked --features linux-integration,update-test-fixtures --test update_transaction_rootful --no-run`, and `git diff --check` passed. Rootful/destructive suites ran only on the disposable hosted runners.
- M005 exact source diff security review: scan `f5ed8a4e-572d-4bba-8522-0a7112da8e50`, zero findings. The reviewed implementation files were `src/distribution.rs`, `src/main.rs`, and `.github/workflows/distribution-foundation.yml`.

## Limitations and release disposition

The measured cold install time and idle RSS are single-run receipts. The native
lifecycle job proves the installed product path on each architecture; the
actual signed updater and real client traffic/recovery qualification ran on
x86_64. Production signing is not provisioned, no production-signed draft was
available, and publication is not authorized. This prevents a public-release
claim but does not invalidate the fixture-backed technical lifecycle evidence.

No unresolved M005 high/medium finding or corrective requirement remains.
No historical closure record was modified. M005 is technically closed and
Phase 10 is **release-mechanically complete, public publication blocked**.

## Successor readiness

Phase 10 closes the IPv4 lifecycle stability prerequisite named by Phase 11.
IPv6/route-policy engineering is therefore unblocked and ready; maintainer
release signing is an independent operational gate. Phase 12 remains deferred
for a separate product decision. The Phase 11 roadmap and first bounded plan
are registered in `plans/subsystems/ipv6-route-policy-roadmap.md` and
`plans/implementation/ipv6-route-policy/001-dual-stack-domain-and-kernel-reconciliation.md`.
