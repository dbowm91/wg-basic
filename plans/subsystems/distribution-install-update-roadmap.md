# Distribution, Installation, Update, and Rollback Roadmap

Status: active; M001–M002 closed, M003 active after Eggpack producer identity prerequisite resolved upstream

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`
- `plans/adr/006-distribution-install-authenticity-and-update.md`
- `architecture/service-hardening.md`
- `architecture/update-rollback-contract.md`

Predecessor state:

- Phase 9 strictly closed at `f5a32c0`;
- update/rollback semantics proven against old schema-v4 and current schema-v5 binaries;
- current head CI green across ordinary, advisory, rootful, and upgrade rehearsal lanes.

## 1. Purpose

Phase 10 turns wg-basic into a distributable Linux appliance with:

- two qualified Linux release artifacts;
- signed release metadata;
- deterministic producer evidence;
- root-owned system installation;
- hardened systemd services;
- explicit first-run state/admin bootstrap;
- transactional self-update over the Phase 9 binary+database contract;
- rollback/recovery journal;
- safe uninstall preserving VPN state by default.

The canonical operator path remains a native binary/service install, not a container.

## 2. Core invariants

1. Release integrity and release authenticity are separate checks.
2. Eggup/Eggpack do not become the product trust root.
3. A release manifest is trusted only after detached-signature verification.
4. The updater accepts only a canonical target and strictly newer stable version.
5. No Cargo/source fallback exists in production install/update.
6. x86_64 and aarch64 artifacts are both native-runtime qualified.
7. An installation is mutated only when binary, units, metadata, and service registrations are proven owned.
8. The state DB remains owned by the unprivileged management account.
9. Update journal/rollback state remains root-owned outside the management-writable state directory.
10. Binary replacement and database migration are one compatibility transaction.
11. A pre-update state backup exists before candidate migration.
12. Update success is not committed until product-owned health validation and a durable commit marker succeed.
13. Default uninstall preserves the secret-bearing state database.
14. The installer/updater never performs implicit privilege escalation.
15. One-command bootstrap trust limitations are stated accurately.
16. Phase 10 does not claim ARMv7, musl, non-systemd Linux, macOS, Windows, TLS termination, or package-manager integration.

## 3. Selected Eggstack primitives

### Eggup

Expected direct dependencies after exact publication/version qualification:

- `eggup-core`;
- `eggup-acquisition`;
- `eggup-curl` (preferred transport);
- `eggup-eggpack`;
- `eggup-service`.

The implementation should prefer exact-compatible published versions proven together, not Git/path dependencies in release builds.

At planning time:

- core/acquisition/eggpack adapter are published at 0.1.3;
- curl/service are published at 0.1.2.

M001/M004 must resolve and pin a registry-only compatible graph and record it.

### Eggpack

Producer tooling remains build-time/release-time only.

The repository will own:

```text
release/eggpack/distribution.toml
release/eggpack/pack.toml
release/eggpack/build-bindings.toml
release/eggpack/qualification-bindings.toml
release/eggpack/consumer-validators.json
release/eggpack/install-policy.toml
release/eggpack/github-policy.json
release/eggpack/github-template.json
release/eggpack/installer-presentation.json
```

plus generated runtime plans/workflow where appropriate.

## 4. Dependency graph

```text
Phase 9 closed
     |
     v
M001 — signed release identity + target contract + verifier
     |
     v
M002 — system install layout + systemd integration
     |
     v
M003 — Eggpack producer pipeline + qualified draft release
     |
     v
M004 — Eggup self-update + durable update journal/rollback
     |
     v
M005 — install/update/uninstall E2E + Phase 10 closure
```

All implementation dependencies are hard.

## 5. M001 — Signed release identity, target contract, and verifier

Status: closed at `plans/closure/distribution/001-status.md`.

Implementation plan:

- `plans/implementation/distribution/001-release-identity-authenticity-and-targets.md`

Objective:

Establish the exact release trust/identity contract before installation or updater code consumes it.

Expected outcomes:

- stable SemVer/version/tag binding;
- canonical x86_64/aarch64 GNU target mapping;
- Eggpack distribution/build/qualification policy files;
- release candidate builds for both targets;
- native target execution;
- glibc-floor qualification;
- Minisign verifier dependency qualified on Rust 1.89;
- test/fixture public key support;
- signature/tamper/wrong-key/downgrade negatives;
- production public-key provisioning seam;
- no updater/install mutation yet.

## 6. M002 — Native system installation and systemd services

Status: closed at `plans/closure/distribution/002-status.md`.

Implementation plan:

- `plans/implementation/distribution/002-system-install-and-service-layout.md`

Objective:

Install one qualified wg-basic binary into the canonical Linux system layout and run the Phase 9 service-hardening contract under real systemd.

Expected outcomes:

- state initialization CLI;
- `netd --allow-user`;
- deterministic unit/sysusers definitions;
- root-owned installation metadata;
- exact layout/ownership/modes;
- systemd registration via Eggup-service;
- install/status commands;
- idempotent owned reinstall/refresh;
- foreign/modified unit refusal;
- fresh install starts netd+serve and doctor passes;
- local admin-bootstrap instructions;
- no self-update yet.

## 7. M003 — Eggpack producer pipeline and signed draft release

Status: active; Eggpack's explicit `v_prefixed_stable_semver` identity mode resolves the prior blocker at reviewed revision `d61ca71fc0112be63e7e8ba31ba8fa2b1ce5a628`. The historical blocked disposition is retained in `plans/closure/distribution/003-status.md`; see the unblock review at `plans/closure/distribution/003-unblock-review.md`.

Implementation plan:

- `plans/implementation/distribution/003-eggpack-release-pipeline-and-signed-draft.md`

Objective:

Make release production deterministic and consumer-compatible without yet publishing an irreversible public release.

Expected outcomes:

- pinned Eggpack revision/tooling;
- generated release workflow from producer contracts;
- exact-tag/source binding;
- locked builds;
- native qualification on x86_64/aarch64;
- artifact size/hash manifest;
- candidate `--version` and release smoke;
- generated installer;
- draft GitHub Release staging;
- detached signature handoff;
- fixture/offline signing path in CI;
- maintainer production-key signing documented as manual gated action;
- producer/consumer manifest agreement test.

## 8. M004 — Transactional self-update and rollback orchestration

Status: blocked on M003.

Implementation plan:

- `plans/implementation/distribution/004-transactional-self-update-and-rollback.md`

Objective:

Implement the Phase 9 update contract with Eggup while retaining wg-basic ownership of authenticity, state migration, health, journal, and commit semantics.

Expected outcomes:

- `update --check`;
- `update`;
- signed manifest acquisition/verification;
- target/version selection;
- exact artifact acquisition;
- Eggup candidate integrity/identity validation;
- root-owned update transaction lock/journal;
- explicit pre-update DB backup;
- service quiescence;
- candidate binary commit;
- candidate migration/start;
- doctor/health/product convergence gate;
- durable update commit marker before Eggup finalization;
- rollback restores compatible DB before old service;
- crash/recovery entrypoint;
- no Cargo fallback.

## 9. M005 — Distribution lifecycle qualification and Phase 10 closure

Status: blocked on M004.

Implementation plan:

- `plans/implementation/distribution/005-install-update-uninstall-e2e-and-phase10-closure.md`

Objective:

Qualify the complete native appliance lifecycle using exact release-like artifacts.

Expected outcomes:

- fresh supported-host install;
- systemd hardening verification;
- admin bootstrap;
- real client setup/traffic after install;
- signed update success;
- failed candidate rollback;
- interrupted update recovery;
- re-update;
- default uninstall preserving state;
- reinstall against preserved state;
- explicit purge + uninstall destructive path;
- release-size/footprint measurements;
- x86_64+aarch64 release qualification;
- first-public-release readiness record;
- Phase 10 closure.

## 10. Target/build contract

Canonical release targets:

| Alias | Rust target | Build | Qualification |
|---|---|---|---|
| linux-x64 | `x86_64-unknown-linux-gnu` | cargo-zigbuild, declared glibc floor | native x86_64 Linux |
| linux-arm64 | `aarch64-unknown-linux-gnu` | cargo-zigbuild, declared glibc floor | native aarch64 Linux |

Qualified floor: glibc 2.17, proven for both native target artifacts by M001.

If a future dependency/toolchain prevents truthful 2.17 support, the producer contract must raise the declared floor to the lowest version actually qualified rather than retaining a copied value.

## 11. Release contract direction

Expected Eggpack contract:

```toml
schema_version = 1

[product]
id = "wg-basic"
display_name = "wg-basic"

[[targets]]
triple = "aarch64-unknown-linux-gnu"
aliases = ["linux-arm64"]

[targets.asset]
kind = "direct"
asset = "{product}-{target}"
install = "{product}"

[targets.checksum]
sidecar = "{asset}.sha256"

[[targets]]
triple = "x86_64-unknown-linux-gnu"
aliases = ["linux-x64"]

[targets.asset]
kind = "direct"
asset = "{product}-{target}"
install = "{product}"

[targets.checksum]
sidecar = "{asset}.sha256"
```

No archive is necessary for the baseline.

## 12. Authenticity envelope

The signed object is exactly `release-manifest.json`.

The signature does not replace per-artifact hash validation; it authenticates the manifest which carries those hashes.

The updater accepts a release only if all are true:

- signature valid under pinned production public key;
- manifest schema valid;
- product ID exactly `wg-basic`;
- release ID exactly the selected version;
- selected target exactly matches host;
- release is strictly newer;
- artifact name/size/hash come from signed manifest.

Installer and release-pipeline signatures use the same project trust root unless a later key-separation plan is accepted.

## 13. Production-key provisioning stop

Implementation agents may create fixture keys for tests.

They MUST NOT:

- create and commit the production private key;
- invent a production public key and call it authoritative;
- upload a private key to GitHub;
- claim production signing is complete without maintainer provisioning.

M001 may close with production signing marked “provisioning-required” only if all verifier/release mechanics are qualified against fixtures and the public-release gate remains blocked.

M003/M005 public-release readiness requires a real committed public key/fingerprint supplied by the maintainer.

## 14. Install metadata

Root-owned `install.json` should include safe authority facts:

- schema version;
- product ID;
- installed release version;
- canonical target;
- installed binary path + SHA-256;
- unit paths + SHA-256;
- sysusers path + SHA-256;
- state directory path;
- runtime directory/socket path;
- service IDs;
- release manifest digest;
- release signing key ID/fingerprint.

It does not contain state DB contents or administrator/session secrets.

This metadata participates in owned refresh/uninstall checks.

## 15. System service shape

Expected units:

```text
wg-basic-netd.service
wg-basic.service
```

Netd:

- system service;
- dedicated network identity;
- CAP_NET_ADMIN only;
- shared socket access for management user;
- fixed socket path;
- no state DB access.

Serve:

- system service;
- dedicated unprivileged management identity;
- state initialization before start;
- fixed state/socket paths;
- loopback HTTP default;
- no capability.

The exact units must implement `architecture/service-hardening.md` and be runtime-tested under systemd, not only string-inspected.

## 16. Init-state command

Add an idempotent command dedicated to service installation, e.g.:

```text
wg-basic state init
```

Semantics:

- if DB absent: create current empty schema under current UID;
- if valid DB present/current-or-migratable: validate/open normally;
- if invalid/foreign/unsafe: fail;
- no network mutation;
- no admin password creation.

This lets systemd initialize the database under the correct service user without root owning the secret file.

## 17. Service-user authorization

Add:

```text
wg-basic netd --allow-user wg-basic
```

Resolution rules:

- exact local account lookup at netd startup;
- account missing -> fail startup;
- resolve to UID once per process start;
- authorized peer policy remains numeric UID comparison at accept time;
- duplicate resolved/numeric UIDs deduplicated;
- usernames never arrive over IPC.

Do not parse arbitrary NSS output through a shell.

## 18. Install command transaction

Fresh install order:

1. require Linux/systemd/root;
2. validate source candidate identity/version;
3. inspect destination ownership/absence;
4. install sysusers definition;
5. create accounts through systemd-sysusers;
6. create/secure state/system/runtime layouts;
7. place executable with Eggup Core or equivalent exact owned transaction;
8. install exact unit definitions through Eggup-service;
9. daemon-reload/enable;
10. initialize state as management user;
11. start netd;
12. start serve;
13. run doctor/health;
14. write root-owned install receipt last;
15. print management URL + admin-bootstrap command.

Failures before the receipt either roll back created program/service files or return explicit recovery-required evidence. Never delete an existing state DB during install rollback.

## 19. Update release discovery

Phase 10 baseline may use the canonical GitHub Releases API or `releases/latest` metadata solely to select a candidate stable SemVer.

Selection metadata is untrusted until the selected release manifest verifies.

Constraints:

- HTTPS canonical repository only;
- response body bounded;
- stable SemVer only;
- no prerelease/draft;
- selected version strictly newer;
- once version is selected, every URL is exact-version, not `latest`;
- signed manifest is the release authority.

## 20. Update journal states

At minimum:

```text
prepared
backup_verified
services_stopped
binary_committed
candidate_started
candidate_healthy
committed
rolling_back
rolled_back
recovery_required
```

Each transition is an atomic durable rewrite with directory durability.

Journal recovery never infers completion from PID/service process state alone.

## 21. Installer generation boundary

Eggpack bootstrap generation is useful for the one-file initial download/integrity path.

System-appliance semantics remain wg-basic-owned.

Preferred generated `install.sh` behavior:

- choose canonical target;
- acquire manifest/signature/artifact;
- verify available authenticity/integrity;
- stage candidate privately;
- execute `wg-basic install --from <candidate-or-self>` or an equivalent root-owned product installer path.

The script does not hand-render systemd unit ownership logic.

## 22. Uninstall contract

Default:

```text
wg-basic uninstall
```

requires root and owned install evidence.

It:

- stops services;
- uninstalls owned units;
- removes sysusers definition when safe;
- removes update journal/old program generations after ownership proof;
- removes binary last;
- preserves `/var/lib/wg-basic`.

If the account remains necessary to own preserved state, default uninstall keeps the management service account/group or explicitly transfers/preserves ownership under a documented rule. Do not orphan a secret DB under a removed numeric identity accidentally.

Destructive flow is separately explicit:

```text
wg-basic network disable
wg-basic state purge --confirm-installation-id ...
wg-basic uninstall --remove-empty-state-identity
```

or an equivalent orchestrated command that uses the same preconditions.

## 23. CI/release evidence

Phase 10 should add separate lanes for:

- release-contract drift;
- target x86_64 build/qualify;
- target aarch64 build/qualify;
- installer systemd E2E on a real/systemd-capable runner or VM;
- signed release fixture;
- update success/rollback/recovery;
- uninstall/reinstall preservation;
- existing Phase 6–9 rootful regression.

Do not weaken the existing rootful matrix merely because release CI is expensive.

## 24. Public-release gate

Phase 10 closure does not automatically publish a release.

A production release requires explicit maintainer authorization after:

- real signing key provisioning;
- signed draft verification;
- both target qualification;
- installer/updater E2E;
- release notes/version/tag match;
- no unresolved high/medium security/distribution finding.

## 25. Milestone status

| Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|
| M001 release identity/authenticity/targets | closed | `plans/implementation/distribution/001-release-identity-authenticity-and-targets.md` | `plans/closure/distribution/001-status.md` |
| M002 system install/service layout | closed | `plans/implementation/distribution/002-system-install-and-service-layout.md` | `plans/closure/distribution/002-status.md` |
| M003 Eggpack producer pipeline/signed draft | active | `plans/implementation/distribution/003-eggpack-release-pipeline-and-signed-draft.md` | Identity seam resolved upstream; exact producer qualification and signing handoff in progress |
| M004 transactional self-update/rollback | blocked | `plans/implementation/distribution/004-transactional-self-update-and-rollback.md` | M003 |
| M005 lifecycle E2E/Phase 10 closure | blocked | `plans/implementation/distribution/005-install-update-uninstall-e2e-and-phase10-closure.md` | M004 |
