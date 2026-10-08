# Distribution M005 — Install/Update/Uninstall E2E and Phase 10 Closure

Status: blocked on Distribution M004 closure

Source roadmap:

- `plans/subsystems/distribution-install-update-roadmap.md#9-m005--distribution-lifecycle-qualification-and-phase-10-closure`

Canonical architecture:

- `plans/adr/006-distribution-install-authenticity-and-update.md`
- `architecture/service-hardening.md`
- `architecture/update-rollback-contract.md`

Primary class: release qualification / product lifecycle / closure

Hard dependency:

- Distribution M004 strict closure.

Production public-release readiness additionally requires:

- maintainer-provisioned production release public key;
- production-signed draft manifest/installer.

Phase 10 technical closure may record that external provisioning as pending, but MUST NOT claim a public release is ready while it is absent.

## 1. Objective

Qualify the complete native wg-basic appliance lifecycle using exact release-like artifacts:

```text
fresh host
 -> install
 -> initialize/admin bootstrap
 -> configure real VPN
 -> signed update
 -> failure rollback/recovery
 -> reinstall/preserve
 -> uninstall preserving state
 -> explicit destructive purge path
```

Close Phase 10 only when the producer, installer, system services, updater, state compatibility transaction, and uninstall behavior agree end to end.

## 2. Exact artifacts under test

M005 qualification consumes artifacts built through the M003 producer contract, not arbitrary local `cargo build` output.

For each canonical target:

- exact binary;
- ReleaseManifest;
- SHA-256;
- detached manifest signature;
- generated installer;
- installer signature where applicable;
- source/tag/release identity receipt.

A local fixture-signed release may be used for destructive CI qualification.

Production-release readiness additionally verifies the maintainer-signed draft.

## 3. Supported-host matrix

Required:

### x86_64 Linux GNU

- native x86_64 systemd-capable environment;
- nftables;
- kernel WireGuard;
- CAP_NET_ADMIN/root test ability;
- curl;
- glibc at or above declared floor.

### aarch64 Linux GNU

- native aarch64 environment with same functional prerequisites.

Both targets must execute the exact published candidate.

At least one architecture must run the full systemd/rootful lifecycle fixture.

The second architecture must run enough systemd/product qualification to prove the service layout is not x86-specific; compile-only is insufficient.

## 4. systemd-capable test environment

Do not assume every GitHub-hosted Linux job is booted with systemd.

Use a qualified runner/VM strategy that provides:

- PID 1 systemd or a truthful isolated system manager;
- root;
- user/group management;
- cgroup/service properties;
- namespace/nft/WireGuard ability.

Record the runner image/kernel/systemd version.

Do not fake systemctl output for final M005 service qualification.

Unit tests may continue to use Eggup-service test doubles.

## 5. Fresh install E2E

Starting from a host with no wg-basic installation:

1. acquire fixture/production-signed release;
2. run bootstrap/high-assurance install path;
3. prove target selection;
4. prove signature/integrity;
5. run root product installer;
6. create service identities/directories;
7. install exact binary/units/sysusers;
8. enable/start netd+serve;
9. candidate state initialization occurs under management UID;
10. install receipt becomes durable;
11. doctor has no required failure;
12. local health responds.

Assert no Cargo, Rust toolchain, Python, Node, or Docker is needed on the host.

Required host runtime dependencies are documented explicitly:

- Linux kernel facilities;
- systemd;
- nftables executable if still the firewall backend;
- curl for the selected update/bootstrap transport.

## 6. Service hardening verification

Inspect actual service manager state, not only unit source.

Prove:

### serve

- exact executable/argv;
- User/Group;
- no effective/ambient capabilities;
- NoNewPrivileges;
- filesystem/home/tmp isolation;
- address-family restriction;
- StateDirectory/path ownership;
- TasksMax/MemoryMax;
- LimitCORE;
- restart policy.

### netd

- exact executable/argv;
- distinct user;
- shared socket group;
- CAP_NET_ADMIN and no additional effective/ambient capability;
- address-family restriction;
- no state DB access;
- no ProtectKernelTunables claim;
- direct forwarding path remains functional.

Use `systemctl show`, `/proc/<pid>/status`, filesystem metadata, and functional tests where appropriate.

## 7. Admin/bootstrap and first product use

After fresh install:

1. set admin password through stdin under management service UID;
2. login over loopback HTTP;
3. perform server setup;
4. create client;
5. export config;
6. configure real client namespace/device;
7. handshake;
8. pass traffic;
9. verify telemetry.

This proves packaging did not alter Phase 8 product behavior.

No unauthenticated browser bootstrap is introduced.

## 8. Update fixture versioning

The current historical repository may not contain two already-published stable versions with distinct package versions.

For CI mechanics, create an isolated fixture old release without changing Git history:

- checkout/copy a known compatible old source into scratch;
- change only the scratch package version to a lower stable fixture version such as `0.0.1`;
- build it through the same target/release contract;
- sign with fixture key;
- clearly mark release ID/product evidence as fixture-only.

Candidate uses the actual current package version and must be strictly newer.

This fixture proves version/update mechanics.

Phase 9's immutable `e8fd6b1` old-binary rehearsal remains the authoritative schema-v4→v5 migration/rollback evidence; do not rewrite history to manufacture a release tag.

If by M005 two real compatible stable release versions exist, prefer them and retire the synthetic version fixture.

## 9. Successful signed update E2E

On the fresh installed old fixture:

- create product state and real client traffic;
- record InstallationId/server public key/client identity/address;
- create authenticated session and audit history;
- run `update --check`;
- prove newer signed candidate found;
- run update;
- preserve pre-update backup/recovery evidence through commit;
- candidate migrates if needed;
- systemd units remain exact owned/hardened;
- candidate health passes;
- durable commit marker written;
- old generation retained/cleaned per policy;
- same client configuration establishes fresh post-update traffic;
- identity/address/product state unchanged unless migration explicitly changes non-identity metadata.

No admin credential is supplied to update.

## 10. Failed-candidate rollback E2E

Cause a post-binary-commit candidate health failure through the environment, not a production bypass flag.

Examples:

- deliberately prevent candidate netd from starting;
- make a required owned system resource unavailable;
- introduce a temporary fixture-only service environment problem.

The failure must occur after:

- pre-update backup;
- services stopped;
- candidate binary committed;
- candidate DB migration when relevant.

Assert:

1. journal reaches pre-commit candidate phase;
2. candidate services stop;
3. old-compatible DB backup restores;
4. Eggup/local transaction restores old binary;
5. old services start;
6. old health passes;
7. same real client passes fresh traffic;
8. journal says RolledBack;
9. no old binary ever starts against new incompatible schema.

## 11. Interrupted-update recovery E2E

For representative phases:

- ServicesStopped;
- BinaryCommitted;
- CandidateStarted;
- CandidateHealthy before Committed.

Externally SIGKILL updater once the durable journal reaches the phase.

Then:

```text
wg-basic update recover
```

must converge to the correct compatible pair.

At least one case should kill after candidate migration so DB restoration is load-bearing.

No production `--crash-at` flag.

## 12. Re-update after rollback

After a successful rollback:

- run update again;
- candidate installs;
- health passes;
- commit marker durable;
- product traffic passes.

This is the Phase 10 automation counterpart to the Phase 9 re-upgrade proof.

## 13. Default uninstall E2E

From a healthy installed system:

```text
wg-basic uninstall
```

or selected final CLI.

Assert:

- services stopped;
- units disabled/removed only if owned;
- daemon reload performed;
- binary removed last;
- root-owned update metadata/recovery material cleaned according to policy;
- secret-bearing `/var/lib/wg-basic` preserved;
- preserved state owner identity remains meaningful.

If preserving state requires keeping `wg-basic` user/group, default uninstall keeps them and states why.

The preserved DB must remain verifiable.

## 14. Reinstall over preserved state

From default-uninstalled host:

1. reinstall exact/newer owned wg-basic;
2. preserve state DB;
3. start services;
4. doctor/state validates;
5. existing admin/session rules remain safe;
6. existing server/client identity returns;
7. existing client config resumes traffic after reconciliation.

This is the primary proof that uninstall does not silently destroy credentials.

## 15. Explicit destructive removal E2E

Exercise the documented destructive operator path:

1. network disable;
2. converge/no owned network state;
3. `state purge --confirm-installation-id ...`;
4. uninstall system files/service identity as allowed.

Prove:

- foreign/unrelated host resources preserved;
- operator-created backups outside owned state path preserved;
- no secret DB remains at canonical live path;
- unit/binary/sysusers owned material removed.

No single “uninstall --force” may bypass purge proof.

## 16. Modified/foreign installation refusal

Before update/uninstall, test:

- binary digest modified;
- serve unit edited;
- netd unit edited;
- sysusers definition edited;
- install metadata edited/permissive/symlink;
- foreign systemd registration.

Expected:

- fail closed;
- no overwrite/removal;
- exact actionable path/category;
- state preserved.

An explicit repair/adopt flow is not required in Phase 10.

## 17. Bootstrap trust qualification

Test both documentation paths.

### Convenience

Run generated HTTPS bootstrap form in a controlled fixture.

Document that trust begins at the downloaded script.

### High assurance

- obtain public key independently;
- download script/manifest/signatures;
- verify detached signatures;
- execute only verified script/candidate.

No docs may imply that embedding a public key in the unverified script authenticates that script.

## 18. Release artifact size/footprint

Record per target:

- binary bytes;
- dynamic library dependencies;
- installed filesystem footprint;
- serve/netd idle RSS under real units;
- cold service readiness;
- update staging/recovery temporary disk need.

Compare with Phase 8/9 engineering signals and explain meaningful growth from Eggup/Minisign dependencies.

Do not weaken security to meet an arbitrary size target.

## 19. Producer/consumer drift gate

Before closure ensure:

- `release/eggpack/distribution.toml`;
- release workflow;
- updater target mapping;
- installer target mapping;
- public artifact names;
- ReleaseManifest parsing

all derive from or are mechanically checked against one canonical contract.

Add CI failure for drift.

No five hand-maintained target tables.

## 20. Public production-key/readiness gate

If production key has been provisioned:

- committed public key fingerprint reviewed;
- exact draft manifest/installer production signatures verify;
- private key absent from repo/CI;
- draft release inventory matches qualification;
- publication checklist complete.

If key has not been provisioned:

- technical Phase 10 implementation may be closed only as **release-mechanically complete, public publication blocked**;
- registry/README must say production signing/public release pending;
- do not call the project production-release-ready.

## 21. Release publication

M005 MUST NOT publish the first irreversible production release automatically.

Prepare a separate maintainer checklist:

- exact tag;
- exact source revision;
- all CI green;
- production signature verification;
- target qualification;
- release notes/support floor;
- no high/medium finding;
- explicit publish action.

Public release is a deliberate maintainer operation after closure/readiness.

## 22. Full regression

Final Phase 10 matrix includes:

- Rust format/check/clippy/tests;
- Rust 1.89;
- cargo-audit;
- all Phase 6–9 rootful suites;
- release contract;
- x86_64 release artifact qualification;
- aarch64 release artifact qualification;
- systemd fresh install;
- successful signed update;
- failed update rollback;
- process-kill recovery;
- uninstall/reinstall preservation;
- destructive purge/uninstall.

Historical closure records remain immutable.

## 23. Documentation reconciliation

Update at least:

- README;
- installation guide;
- update/recovery guide;
- state backup/restore docs;
- operations runbook;
- service-hardening doc with final units/measurements;
- update-rollback contract with implemented journal/CLI;
- release/security policy;
- Phase 10 roadmap/registry;
- support matrix.

State accurately:

- supported Linux/systemd architectures/floor;
- required host dependencies;
- bootstrap trust;
- release signing;
- default uninstall preservation;
- recovery procedure;
- unsupported ARMv7/musl/non-systemd hosts;
- Phase 11 IPv6 remains pending.

## 24. Acceptance criteria

M005 closes only when:

1. exact x86_64 and aarch64 release artifacts are natively qualified;
2. a fresh supported systemd host installs without Rust/Python/Node/Docker;
3. actual services satisfy Phase 9 hardening/privilege contracts;
4. fresh product setup establishes real WireGuard traffic;
5. signed newer update succeeds and preserves identity/traffic;
6. post-migration health failure rolls DB+binary back in correct order;
7. interrupted pre-commit updates recover deterministically;
8. rollback can be followed by successful re-update;
9. default uninstall preserves secret state and reinstall reuses it;
10. destructive removal requires existing purge proof;
11. modified/foreign files/units are never overwritten/removed;
12. producer/updater/installer artifact identities cannot drift silently;
13. bootstrap trust is documented honestly;
14. no unresolved high/medium distribution/security finding remains;
15. all historical rootful/security/MSRV tests remain green;
16. public release readiness is truthfully gated on production signing if still outstanding.

## 25. Stop conditions

Stop/write corrective if:

- supported target artifact only works on build host but not representative native host;
- systemd hardening differs materially from Phase 9 contract without review;
- update rollback starts an incompatible old binary against migrated state;
- updater crash can leave no trustworthy recovery pair;
- uninstall can orphan state under a deleted service identity;
- bootstrap docs overclaim authenticity;
- a release would need a force-unsigned path;
- Phase 10 closure would require publishing an irreversible release merely to collect evidence.

## 26. Closure evidence

Record:

- exact release/tag/source/target inventory;
- systemd host/runner/kernel evidence;
- install filesystem/user/group/capability receipts;
- first product traffic;
- successful signed update trace;
- failed candidate rollback trace;
- SIGKILL recovery traces;
- re-update trace;
- uninstall/reinstall preservation;
- destructive purge/uninstall;
- modified/foreign refusal matrix;
- per-target footprint/compatibility;
- production signing/publication disposition;
- complete CI matrix;
- Phase 10 closure and Phase 11 readiness recommendation.
