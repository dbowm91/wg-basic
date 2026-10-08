# ADR-006 — Distribution, Installation, Release Authenticity, and Update Orchestration

Status: accepted

Date: 2026-10-08

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`
- `architecture/service-hardening.md`
- `architecture/update-rollback-contract.md`

Predecessor state:

- Phases 1–9 are strictly closed;
- current head `f5a32c0` is green across ordinary, advisory, rootful, and upgrade-rehearsal CI.

## 1. Context

Phase 10 turns the complete Linux appliance into something an operator can install, run under systemd, update, roll back, and uninstall without Docker, Node, Python, Cargo, or a language runtime.

Phase 9 already proved the difficult state transaction:

- old binary + old database are one compatibility pair;
- a secret-bearing pre-update state snapshot is mandatory before migration;
- candidate health is verified after migration;
- an old binary correctly refuses a newer schema;
- rollback restores the compatible database before restarting the old binary;
- the candidate can re-upgrade the restored state.

Phase 10 must automate that contract without moving release authenticity, migration policy, or product-health decisions into generic Eggstack libraries.

## 2. Eggstack research findings

### 2.1 Eggup

Current Eggup is Rust 1.89 and splits responsibilities cleanly.

Selected primitives:

- `eggup-core`: staging, SHA-256 integrity, bounded candidate validation, destination ownership revalidation, mutation lock, replacement/rollback receipts;
- `eggup-acquisition`: bounded transport-neutral acquisition contract;
- one HTTP adapter selected by wg-basic policy;
- `eggup-eggpack`: ReleaseManifest v1 projection into exact acquisition and artifact-set inputs;
- `eggup-service`: systemd registration/lifecycle mechanics with exact executable/argv ownership and no automatic privilege escalation.

Eggup explicitly makes no release-authenticity claim.

Its local transaction may run a caller-owned post-commit check before finalizing the prior artifact generation. wg-basic can therefore make the durable update commit marker part of its post-install success path, so Eggup does not discard rollback bytes before wg-basic's own transaction commits.

### 2.2 Eggpack

Eggpack 0.1.x provides:

- canonical target/release naming contract;
- deterministic build and qualification planning;
- ReleaseManifest v1 containing artifact size/SHA-256 evidence;
- bootstrap installer generation;
- draft GitHub Release staging.

Eggpack deliberately does not:

- sign releases;
- elevate privilege;
- install services;
- edit PATH;
- overwrite an existing installation;
- define updater/product policy.

wg-basic will use Eggpack as producer tooling, not as the system-appliance installer.

## 3. Decision: canonical platform

Phase 10 remains Linux-only.

Canonical service manager:

- systemd system scope.

The installer fails with a clear unsupported-host result when systemd is unavailable.

No launchd, Windows SCM, OpenRC, runit, cron fallback, or container becomes part of the Phase 10 support claim.

Other service managers can be researched later without changing the runtime roles.

## 4. Decision: release target matrix

Required production targets:

```text
x86_64-unknown-linux-gnu
aarch64-unknown-linux-gnu
```

Aliases:

```text
linux-x64
linux-arm64
```

Build policy:

- release profile;
- locked Cargo graph;
- Eggpack producer contract is the naming/target authority;
- Linux builds use cargo-zigbuild with a glibc 2.17 floor if qualification confirms the complete wg-basic dependency graph supports that floor;
- each artifact executes and is qualified on a native runner of the same architecture;
- aarch64 uses a native Linux ARM runner, not compile-only evidence.

Not Phase 10 baseline:

- `armv7-unknown-linux-gnueabihf`;
- musl artifacts;
- macOS;
- Windows.

ARMv7 requires executable/emulated plus representative kernel/network qualification before publication.

GNU is preferred over musl because the appliance already depends on a conventional systemd/nftables Linux host; musl does not eliminate those host dependencies and would add another libc support surface.

## 5. Decision: release identity

Public releases use stable SemVer only in Phase 10.

Required bindings:

- Cargo package version = `X.Y.Z`;
- Git tag = `vX.Y.Z`;
- candidate `wg-basic --version` = `wg-basic X.Y.Z`;
- Eggpack release identity = `X.Y.Z`;
- signed ReleaseManifest product ID = `wg-basic`;
- release source revision = exact tagged commit.

No prerelease/nightly channel in the Phase 10 baseline.

The updater rejects same-version and downgrade candidates. Automatic rollback is a separate transaction using the retained previous generation; it is not implemented as a user-requested downgrade.

## 6. Decision: release artifact set

For each target publish one direct executable:

```text
wg-basic-x86_64-unknown-linux-gnu
wg-basic-aarch64-unknown-linux-gnu
```

Each has a SHA-256 sidecar generated by the producer pipeline.

Release metadata includes:

```text
release-manifest.json
release-manifest.json.minisig
install.sh
install.sh.minisig
```

The release manifest is Eggpack-generated canonical JSON and binds target, artifact name, exact byte count, and SHA-256.

No tarball is required for the baseline because the runtime product is one executable and system integration is generated by that executable.

## 7. Decision: release authenticity

SHA-256 evidence is integrity, not authenticity.

The canonical authenticity root is a Minisign/Ed25519 release key controlled by the wg-basic project.

Release policy:

1. Eggpack builds, qualifies, and stages a draft release.
2. The exact staged `release-manifest.json` is downloaded to a trusted signing environment.
3. A release signing key that is not stored in the repository or ordinary GitHub Actions signs the exact manifest bytes.
4. The detached `.minisig` is uploaded to the draft.
5. A release verification step checks signature, product/release/source bindings, all artifact hashes/sizes, and target qualification before publication.

The private signing key MUST NOT be committed, embedded in workflow secrets by default, or generated by an implementation agent and discarded.

The public verification key and its human-display fingerprint/key ID are committed to the repository and embedded into release-verification code after maintainer provisioning.

Initial implementation may use a fixture key solely for tests. Production release publication is blocked until the real public trust root is provisioned and reviewed.

## 8. Decision: verifier implementation

Preferred runtime verifier candidate:

- `minisign-verify` 0.3.x.

Reasons:

- verify-only;
- standard Minisign format;
- Ed25519;
- streaming/file verification support;
- zero external Rust dependencies in the current crate;
- avoids pulling a Sigstore/OIDC/transparency-log client into the appliance.

The owning milestone must prove:

- Rust 1.89 compilation;
- expected public-key/signature parsing;
- tamper/wrong-key/wrong-manifest rejection;
- no signing capability or private-key handling in the shipped binary.

If that crate fails MSRV/security qualification, use an equivalently narrow verify-only Ed25519 implementation rather than weakening authenticity.

## 9. Decision: Sigstore/GitHub attestations

GitHub artifact attestations/Sigstore provenance are useful supplementary release evidence.

They are not the canonical updater trust root in Phase 10.

Reasons:

- updater verification should not require `gh`, `cosign`, OIDC identity policy, or an online transparency-log query;
- Minisign gives a small pinned offline trust root;
- provenance and maintainer signing answer related but distinct questions.

The release pipeline MAY publish GitHub build provenance/attestations and document how operators verify them externally.

## 10. Decision: bootstrap trust

A one-command installer cannot cryptographically authenticate itself using code contained only inside that same downloaded script.

Canonical convenience command therefore has an explicit bootstrap-channel trust boundary:

```text
curl -fsSL <canonical GitHub/raw installer URL> | sudo sh
```

The script trusts the HTTPS/GitHub delivery of the script itself.

It then:

- downloads the release manifest, manifest signature, and selected artifact;
- verifies SHA-256 evidence;
- when an external Minisign verifier is available, verifies the detached signature before execution;
- delegates local installation semantics to the downloaded wg-basic candidate.

High-assurance installation is separately documented:

1. obtain the public key/fingerprint out of band;
2. download installer/manifest/signatures;
3. verify detached signatures with Minisign;
4. run the verified installer/candidate.

Do not describe the convenience `curl | sudo sh` path as end-to-end cryptographically authenticated.

## 11. Decision: update authenticity

Self-update has a stronger trust boundary than bootstrap.

The installed trusted binary contains the pinned public release key.

Before an update candidate is materialized as trusted release metadata, the updater:

1. selects an exact stable release from the canonical GitHub repository;
2. downloads bounded `release-manifest.json` and `.minisig`;
3. verifies the signature using the embedded key;
4. verifies product ID, exact release version, selected target, and version monotonicity;
5. lets `eggup-eggpack` project exact artifact size/SHA-256;
6. downloads the artifact under those exact bounds;
7. lets Eggup verify integrity again and run bounded exact `--version` candidate validation.

An attacker controlling unsigned GitHub/API metadata can at most cause denial/withholding; it cannot make an unsigned or downgraded binary pass the update policy.

No Cargo/source fallback exists.

## 12. Decision: update transport

Preferred baseline: `eggup-curl` over `eggup-acquisition`.

Reason:

- canonical bootstrap already requires curl;
- external-curl adapter has a dramatically smaller link/dependency footprint than an embedded Rustls HTTP stack;
- update traffic is infrequent;
- Eggup provides bounded argv/no-shell transport behavior;
- wg-basic remains a small appliance binary.

Requirements:

- discover/resolve curl only from an allowlisted absolute path;
- fail clearly if curl is absent;
- HTTPS only;
- strict HTTPS→HTTP downgrade rejection;
- bounded connect/total deadlines;
- manifest/signature metadata bounds;
- artifact bound tightened to signed manifest exact size;
- no generic proxy/auth string in logs.

Before final adoption, implementation must compare release binary size/dependency delta against `eggup-eggfetch`. If curl availability or safety evidence is inadequate on the supported distributions, M003 may select `eggup-eggfetch` with a recorded ADR amendment/evidence rather than silently changing transports.

## 13. Decision: filesystem/install layout

Canonical system installation:

```text
/usr/local/bin/wg-basic
/etc/systemd/system/wg-basic-netd.service
/etc/systemd/system/wg-basic.service
/etc/sysusers.d/wg-basic.conf

/var/lib/wg-basic/
    state.db
    state.db.serve.lock
    state.db.maintenance.lock
    ...state-owned recovery artifacts...

/var/lib/wg-basic-system/
    install.json
    update-journal.json
    rollback/
        <transaction-id>/

/run/wg-basic/
    netd.sock
```

Ownership:

- binary/unit/sysusers definition: root-owned;
- `/var/lib/wg-basic`: management service account, 0700;
- `/var/lib/wg-basic-system`: root-owned, 0700;
- update rollback state snapshots: root-owned, 0600;
- runtime socket: netd-owned with the management group allowed to connect.

The root-owned installation metadata/journal is not stored under the management-service-writable state directory.

No product config file is required in the baseline; systemd ExecStart uses explicit fixed arguments/default paths.

## 14. Decision: service identities

Canonical accounts:

- `wg-basic`: unprivileged management/state owner;
- `wg-basic-netd`: privileged network role;
- shared group `wg-basic` for the netd Unix socket.

Accounts are provisioned declaratively through systemd-sysusers or an equivalent fixed systemd facility, not by shell interpolation.

To avoid hardcoding installation-time numeric UIDs into unit files, netd gains a product-owned `--allow-user wg-basic` form that resolves the account to an exact UID at process start and feeds the existing peer-credential authorization policy.

The existing `--allow-uid` remains available for development/testing if useful.

## 15. Decision: state initialization/admin bootstrap

The service unit runs an idempotent unprivileged state-initialization command before `serve`, under the `wg-basic` service account.

This creates an empty valid state database safely under the existing owner/mode rules.

The installer does not create an administrator through an unauthenticated browser path.

After first installation it prints the explicit local bootstrap command, conceptually:

```text
sudo -u wg-basic /usr/local/bin/wg-basic admin set-password --password-stdin
```

A later convenience wrapper may run this exact operation under the service UID, but secrets must never enter argv/environment and the canonical installer must remain usable when stdin is occupied by `curl | sh`.

## 16. Decision: concrete systemd units

Phase 10 ships system-scope units implementing `architecture/service-hardening.md`.

Ordering:

```text
network-online.target
        |
        v
wg-basic-netd.service
        |
        v
wg-basic.service
```

`serve` requires/starts after netd.

netd unit uses:

- `User=wg-basic-netd`;
- shared group/access needed for its socket;
- CAP_NET_ADMIN only;
- no `ProtectKernelTunables=yes`;
- `RuntimeDirectory=wg-basic` or equivalently qualified runtime-directory management.

serve uses:

- `User=wg-basic`;
- no capabilities;
- `StateDirectory=wg-basic` where compatible with the fixed state path;
- the Phase 9 resource/isolation controls.

Exact unit bytes are product-owned release artifacts/material.

## 17. Decision: service registration ownership

Eggup-service classifies service ownership by exact executable + critical argv. That is necessary but not sufficient for wg-basic because an operator could modify hardening directives without changing ExecStart.

wg-basic therefore adds a stronger product-level unit ownership check before refresh/removal:

- installed unit must be a regular root-owned file;
- exact current unit bytes/digest must match one of the wg-basic definitions recorded by the current installation metadata;
- observed systemd ExecStart ownership must also be `Owned`.

If unit content is foreign/modified/unknown, update/uninstall fails closed and reports the path.

Do not overwrite local service hardening edits merely because ExecStart still points at wg-basic.

## 18. Decision: installer privilege model

The system installer requires root.

It does not invoke sudo or attempt privilege escalation internally.

Expected forms:

```text
curl ... | sudo sh
sudo ./wg-basic install
```

If not root, it exits with an actionable instruction.

The installer is idempotent only for an exactly owned wg-basic installation. Foreign files/units/users are never adopted destructively.

## 19. Decision: install command scope

Add product-owned system commands approximately:

```text
wg-basic install
wg-basic install status
wg-basic uninstall
wg-basic update
wg-basic update --check
```

Exact CLI nesting may be refined by the implementation plan.

Install owns:

- layout preflight;
- users/group;
- directories;
- binary placement;
- systemd definitions;
- enable/start;
- doctor/health smoke;
- bootstrap instructions;
- root-owned install metadata.

Install does not silently purge an existing VPN database.

## 20. Decision: uninstall

Default uninstall:

- stops/disables owned services;
- removes owned unit/sysusers definitions;
- removes owned program/update metadata files;
- removes the program binary last;
- preserves `/var/lib/wg-basic/state.db`, backups, keys, and product state;
- prints exact preserved state path and reinstall/recovery guidance.

Destructive state removal is an explicit separate operation using the already-qualified `state purge` contract, optionally orchestrated before uninstall only with the same InstallationId confirmation.

Uninstall never turns “remove program” into implicit credential destruction.

## 21. Decision: updater journal

The root-owned update journal is the transaction state machine Phase 9 intentionally left for Phase 10.

It records only safe metadata:

- transaction ID;
- current/candidate versions;
- target;
- source release identity;
- current binary digest;
- signed manifest digest/key ID;
- state installation ID/generation/schema;
- pre-update backup path/digest;
- phase;
- candidate/old binary recovery paths;
- durable commit marker.

No database contents, tokens, keys, configs, HTTP credentials, or signing secrets.

Journal writes are atomic and file + parent directory durability is explicitly qualified.

A crash before the commit marker is uncommitted and follows `architecture/update-rollback-contract.md`.

## 22. Decision: Eggup transaction composition

wg-basic owns orchestration around Eggup:

```text
signed release selection
 -> Eggup acquisition/integrity/candidate validation
 -> pre-update DB snapshot
 -> stop serve + netd through Eggup-service
 -> Eggup binary commit
 -> start candidate netd + serve
 -> product-owned health gate
 -> write+sync durable update commit marker
 -> return successful post-commit check
 -> Eggup may finalize prior binary backup
```

If the post-install health gate fails:

1. stop candidate services;
2. restore the compatible pre-update DB;
3. return post-commit failure;
4. Eggup rolls the binary back;
5. start old services;
6. validate old health;
7. retain recovery evidence/journal.

The update commit marker MUST be durable before wg-basic allows Eggup's success path to discard the old binary backup.

## 23. Decision: update health gate

Automated update does not require an administrator password/session.

Required local gate:

- both systemd services owned and running;
- candidate doctor has no required Fail;
- `/healthz` is exactly `ok` for an enabled healthy installation;
- local management health reports reachable backend and converged current generation;
- product/state read validates current installation semantics.

Release CI continues to own real handshake/traffic qualification for the exact release artifact. An individual production update does not fabricate a new client solely for a traffic smoke test.

## 24. Decision: producer pipeline

Eggpack is the producer source of truth.

Phase 10 adds a `release/eggpack/` contract similar in shape to other Eggstack consumers but narrowed to the two Linux targets.

The generated/pinned workflow must:

- build from an exact existing tag/source revision;
- use pinned GitHub Actions and pinned Eggpack revision;
- build locked release binaries;
- enforce glibc floor;
- qualify each artifact natively;
- run wg-basic candidate/version smoke;
- run target-appropriate product/rootful release qualification;
- finalize ReleaseManifest/checksums;
- stage a draft GitHub Release.

Publishing is a separate maintainer-authorized action after detached-signature verification.

## 25. Decision: first-public-release gate

Phase 10 implementation/qualification can close against a signed local/draft-release fixture without irreversibly publishing a GitHub Release.

The first public release is a separate explicit maintainer action.

Before publication:

- real production public key provisioned;
- manifest and installer signatures present/verified;
- exact source/tag/version bindings proven;
- both release targets qualified;
- installer fresh-host test passes;
- update/rollback from a prior fixture release passes;
- dependency/security gates green;
- release notes accurately state supported hosts and bootstrap trust.

## 26. Consequences

Positive:

- canonical deployment remains a small Linux system install, not Docker;
- Eggup/Eggpack are reused within their actual boundaries;
- release integrity and authenticity are explicitly distinct;
- updater trust is offline-capable and small;
- service units implement the already-qualified Phase 9 hardening contract;
- database rollback and binary rollback remain one transaction;
- default uninstall preserves credentials/state;
- x86_64 and aarch64 cover the primary server/SBC deployment classes.

Costs:

- curl remains a runtime prerequisite for self-update in the preferred baseline;
- first-install `curl | sh` cannot escape bootstrap-channel trust;
- signing requires an out-of-band key-management step;
- installer/update orchestration is product-specific despite generic Eggup mechanics;
- Phase 10 remains systemd/Linux specific.

## 27. Verification consequences

Phase 10 closure must prove:

- both canonical target artifacts build and execute natively;
- glibc floor or other declared compatibility floor is real;
- signed-manifest verification is load-bearing;
- wrong key/tampered manifest/artifact/downgrade all fail;
- fresh systemd installation produces the exact service-hardening profile;
- service accounts/socket/state permissions are correct;
- install is idempotent only for owned state;
- update follows the Phase 9 binary+DB transaction and journal crash matrix;
- failed candidate restores compatible state and old binary/services;
- uninstall preserves state by default;
- release producer contract and consumer updater agree on every artifact identity.
