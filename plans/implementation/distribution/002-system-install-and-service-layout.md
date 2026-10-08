# Distribution M002 — System Install and Service Layout

Status: closed

Source roadmap:

- `plans/subsystems/distribution-install-update-roadmap.md#6-m002--native-system-installation-and-systemd-services`

Canonical architecture:

- `plans/adr/006-distribution-install-authenticity-and-update.md`
- `architecture/service-hardening.md`

Primary class: installation / service ownership / privilege separation

Hard dependency:

- Distribution M001 strict closure at `plans/closure/distribution/001-status.md`.

## 1. Objective

Install one already-qualified wg-basic executable as a native systemd-managed Linux appliance while preserving the Phase 1–9 privilege, state-ownership, and recovery contracts.

M002 implements fresh install and owned refresh/status only.

It does not implement network release discovery, self-update, signed draft publication, or automatic rollback across versions.

## 2. Required Eggup dependencies

Adopt only the registry-qualified crates proven by M001.

Expected direct crates:

- `eggup-core` for staged local executable placement/ownership-safe refresh;
- `eggup-service` for systemd registration/lifecycle mechanics.

Do not add acquisition or Eggpack adapter crates solely for M002.

No Git/path dependency in a release-capable build.

## 3. Canonical layout

Implement exactly one system installation profile:

```text
/usr/local/bin/wg-basic

/etc/systemd/system/wg-basic-netd.service
/etc/systemd/system/wg-basic.service
/etc/sysusers.d/wg-basic.conf

/var/lib/wg-basic/
/var/lib/wg-basic-system/

/run/wg-basic/
```

State DB stays at the existing default:

```text
/var/lib/wg-basic/state.db
```

Netd socket stays:

```text
/run/wg-basic/netd.sock
```

No relocatable prefix is required for production M002.

Tests may bind the same layout semantics under a disposable fake/root prefix where service-manager mechanics are mocked.

## 4. Ownership and permissions

Required:

### Program/system definitions

- binary: root:root, executable, not group/world writable;
- systemd units: root:root, 0644;
- sysusers definition: root:root, 0644;
- installation metadata directory: root:root, 0700;
- installation metadata: root:root, 0600.

### Product state

- state directory: `wg-basic` management user, 0700;
- DB/recovery artifacts preserve existing owner-only contract;
- management service is the only ordinary DB owner.

### Runtime

- runtime directory has deterministic systemd ownership/mode;
- netd socket is writable/connectable only by the intended service principals;
- unrelated users cannot connect successfully.

Do not relax StateStore owner/mode validation to accommodate installation.

## 5. Service identities

Create the system identity policy:

- management user: `wg-basic`;
- privileged network user: `wg-basic-netd`;
- shared group: `wg-basic`.

Prefer systemd-sysusers.

The generated `wg-basic.conf` must be fixed product material, not templated from untrusted input.

The netd unit should run:

- `User=wg-basic-netd`;
- `Group=wg-basic`.

This makes the Unix socket group `wg-basic` while keeping netd's UID distinct from the state owner.

The serve unit runs:

- `User=wg-basic`;
- `Group=wg-basic`.

## 6. netd username authorization

Extend CLI:

```text
wg-basic netd --allow-user wg-basic
```

Semantics:

- resolve local username through a safe libc/NSS-capable Rust API;
- no shell;
- bounded username syntax;
- missing/ambiguous account -> netd startup failure;
- convert to numeric UID once at startup;
- add to existing peer-credential `AuthorizationPolicy`;
- deduplicate against any explicit `--allow-uid` values.

IPC authorization remains numeric `SO_PEERCRED` matching.

Tests:

- known fixture account lookup seam;
- missing user;
- duplicate numeric/user entry;
- control/overlong username;
- existing `--allow-uid` behavior unchanged.

Do not make usernames part of wire protocol.

## 7. State initialization command

Add:

```text
wg-basic state init [--state <path>]
```

Semantics:

- if state does not exist, create current empty schema using existing StateStore initialization under current effective UID;
- if current/migratable owned state exists, open/validate/migrate normally and exit success;
- unsafe parent, wrong owner, symlink, corrupt DB, or newer schema -> fail;
- no network IPC;
- no interface/firewall mutation;
- no administrator creation;
- no default VPN configuration.

This command is safe/idempotent for systemd `ExecStartPre`.

## 8. Product-owned systemd definitions

Create exact unit-definition renderer/constants in a dedicated distribution/service module.

### wg-basic-netd.service

Must implement the Phase 9 hardening contract, including:

- `User=wg-basic-netd`;
- `Group=wg-basic`;
- CAP_NET_ADMIN only;
- `NoNewPrivileges=yes`;
- strong filesystem/home/tmp isolation;
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK`;
- `LimitCORE=0`;
- Phase 9 initial `TasksMax`/`MemoryMax`;
- bounded restart policy;
- explicit `ExecStart=/usr/local/bin/wg-basic netd --socket /run/wg-basic/netd.sock --allow-user wg-basic`;
- runtime directory creation/ownership.

Do not set `ProtectKernelTunables=yes`.

### wg-basic.service

Must include:

- `Requires=wg-basic-netd.service`;
- `After=wg-basic-netd.service network-online.target` or the smallest correct ordering established by tests;
- `User=wg-basic`;
- `Group=wg-basic`;
- no capabilities;
- Phase 9 hardening controls;
- state-directory ownership;
- `ExecStartPre=/usr/local/bin/wg-basic state init --state /var/lib/wg-basic/state.db`;
- `ExecStart=/usr/local/bin/wg-basic serve ...`;
- loopback HTTP default.

No shell in ExecStart.

## 9. systemd ownership strengthening

Eggup-service proves:

- unit name;
- executable;
- critical argv;
- manager lifecycle.

wg-basic additionally proves exact product unit bytes.

Before refresh/uninstall:

1. unit path is regular file/no symlink;
2. root owned;
3. safe mode;
4. SHA-256 equals the digest recorded in root-owned install metadata for the installed generation;
5. Eggup-service inspection classifies the registration `Owned`.

If bytes differ, classify as modified/foreign and fail closed.

Never overwrite a locally modified hardening unit silently.

## 10. Installation metadata

Create versioned `/var/lib/wg-basic-system/install.json`.

Required fields:

- metadata schema;
- product ID;
- installed wg-basic version;
- canonical target;
- installed binary absolute path and SHA-256;
- unit paths and SHA-256 values;
- sysusers path and SHA-256;
- state directory/path;
- system metadata directory;
- runtime/socket path;
- service IDs;
- source release identity when available;
- release-manifest digest when available;
- signing key ID/fingerprint when available.

Fresh local candidate install may mark release provenance as local/fixture but must never fabricate a signature identity.

Atomic private write + file and parent durability required.

## 11. Installation transaction lock

Add a root-owned install/update/uninstall lock under:

```text
/var/lib/wg-basic-system/
```

It is distinct from:

- StateStore serve lease;
- maintenance lock;
- Eggup core member lock.

It serializes system installation/update/uninstall orchestration.

Use a crash-released advisory kernel lock plus safe root-owned path checks.

No PID-file trust.

## 12. CLI surface

Add a bounded product-owned surface approximately:

```text
wg-basic install
wg-basic install status
```

The exact Clap nesting may be:

```text
wg-basic system install
wg-basic system status
```

if that keeps state/network subcommands clearer.

Pick one and reconcile docs/roadmap.

Fresh install requires effective root.

If non-root:

- no mutation;
- actionable message;
- no internal sudo execution.

## 13. Fresh installation sequence

The implementation must preserve this ordering:

1. acquire root-owned system transaction lock;
2. verify Linux + systemd system manager;
3. verify current executable identity/candidate;
4. prove binary/unit/sysusers destinations absent or owned;
5. install/refresh sysusers definition;
6. invoke `systemd-sysusers` through an allowlisted absolute path with bounded execution;
7. verify resulting users/group;
8. ensure root/system metadata and state parent layouts with exact ownership;
9. use Eggup Core to place/refresh executable with ownership revalidation;
10. install netd unit through Eggup-service;
11. install serve unit through Eggup-service;
12. daemon-reload and enable;
13. start netd;
14. start serve, whose ExecStartPre initializes state as `wg-basic`;
15. run read-only doctor/health smoke;
16. write the install receipt last;
17. print local management URL and admin bootstrap instructions.

If state DB pre-exists and is safely owned by the expected management UID, preserve it.

No install rollback may delete a pre-existing valid state DB.

## 14. Candidate/executable ownership

Fresh installer may be invoked from a downloaded staging path.

The installed destination is always `/usr/local/bin/wg-basic`.

Candidate validation:

- regular file/no symlink;
- root caller can read it;
- exact `--version` identity;
- selected target consistent with current host;
- if signed release provenance is supplied, it must match M001 evidence;
- executable intent.

Owned refresh:

- current binary digest must equal install metadata;
- destination root ownership/mode safe;
- version policy in M002 may permit exact-version repair/reinstall but not downgrade.

Version upgrade is reserved for M004.

## 15. systemd command boundary

Prefer Eggup-service `SystemdManager`.

For sysusers, if Eggup-service has no sysusers primitive, use one product-owned bounded command seam:

- absolute `/usr/bin/systemd-sysusers` or qualified distro path;
- no shell;
- cleared/minimal environment;
- bounded output/time;
- exact definition path;
- error redaction.

Do not introduce a generic subprocess wrapper exposed to product input.

## 16. Install status

Read-only `install status` should report:

- install metadata validity;
- binary digest/version/target ownership;
- unit-file byte ownership;
- Eggup-service registration/lifecycle ownership;
- state directory owner/mode;
- runtime/socket status;
- doctor aggregate disposition.

No secrets.

Exit status distinguishes healthy/attention/failure.

## 17. Admin bootstrap output

After fresh install, print:

```text
Management UI: http://127.0.0.1:<port>
Create/reset admin:
  sudo -u wg-basic /usr/local/bin/wg-basic admin set-password --password-stdin
```

The installer does not ask for a password when run under piped stdin.

No password in argv/environment.

## 18. Tests

### Unprivileged/unit

- exact unit snapshots;
- no forbidden `ProtectKernelTunables=yes`;
- exact hardening directives;
- install metadata parse/digest checks;
- unit modification refused;
- foreign binary refused;
- transaction lock exclusivity;
- state init idempotence;
- username-to-UID policy seam;
- non-root install refuses before mutation.

### systemd-capable integration

On a real systemd host/VM:

- fresh install from staging candidate;
- users/groups created;
- units installed and enabled;
- exact service UIDs/GIDs/capabilities;
- state DB management-owned 0600 under 0700 dir;
- netd cannot open state DB;
- serve has no CAP_NET_ADMIN;
- netd has CAP_NET_ADMIN and no extra effective capability;
- socket authorizes management user and rejects unrelated user;
- doctor has no required failure after startup;
- `/healthz` responds;
- exact owned reinstall succeeds;
- modified unit causes refresh refusal.

## 19. Acceptance criteria

M002 closes only when:

1. canonical root/state/runtime layout is implemented;
2. service users/group are deterministic;
3. state is initialized under management UID, never root-owned;
4. systemd units implement Phase 9 hardening and run successfully;
5. netd receives only intended capability and socket authorization;
6. full unit-byte ownership protects operator changes;
7. root-owned install metadata/lock are safe and durable;
8. install is idempotent only for owned installations;
9. pre-existing valid VPN state survives install/repair;
10. fresh installed services pass doctor/health;
11. no self-update/release discovery exists yet;
12. all prior CI and Rust 1.89 pass.

## 20. Stop conditions

Stop/write a corrective if:

- systemd cannot provide the required state/runtime ownership without weakening StateStore validation;
- netd requires a capability beyond CAP_NET_ADMIN;
- service units need shell interpolation;
- Eggup-service cannot fail closed on service ownership;
- exact unit-byte ownership cannot coexist with systemd registration mechanics;
- install needs to create the secret DB as root;
- supporting a distro requires silently falling back to a different service manager.

## 21. Closure evidence

Record:

- exact layout/modes/UID/GID policy;
- unit definitions/digests;
- capabilities and address-family evidence;
- state-init ownership proof;
- systemd install/status/reinstall/modified-unit fixtures;
- Eggup-service version/API usage;
- dependency/footprint delta;
- doctor/health after fresh install;
- all CI/MSRV;
- M003 readiness.
