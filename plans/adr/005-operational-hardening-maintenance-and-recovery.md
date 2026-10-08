# ADR-005 — Operational Hardening, Maintenance, and Recovery Contracts

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

Predecessor state:

- Phases 1–8 strictly closed;
- current head `e8fd6b1` is green across ordinary Rust and every rootful qualification job.

## 1. Context

wg-basic now has a complete user-facing IPv4 product path but does not yet have the operational behavior required for a production appliance release.

Existing primitives are strong:

- deterministic network ownership and reconciliation;
- durable generation-CAS state;
- online backup and validated offline restore;
- startup/crash recovery;
- bounded HTTP and privileged IPC;
- local admin/session security;
- product CRUD/export/enrollment/telemetry/audit;
- low runtime footprint.

Phase 9 must harden how operators diagnose, stop, recover, stress, and upgrade that product without prematurely implementing Phase 10 distribution/update machinery.

## 2. Current research findings

### 2.1 SQLite

wg-basic currently resolves `rusqlite` 0.40.x with `libsqlite3-sys` 0.38.2 and bundled SQLite 3.53.2.

SQLite's WAL-reset corruption bug affected WAL mode through SQLite 3.51.2 and was fixed in 3.51.3. The bundled 3.53.2 runtime is beyond that fix.

Phase 9 therefore records and verifies the actual SQLite runtime/source identity in diagnostics rather than introducing a database replacement.

### 2.2 systemd hardening

The intended Phase 10 service manager is systemd on Linux distributions that provide it.

Useful hardening controls include:

- `NoNewPrivileges=`;
- `CapabilityBoundingSet=`;
- `ProtectSystem=`;
- `ProtectHome=`;
- `PrivateTmp=`;
- `RestrictAddressFamilies=`;
- `MemoryMax=`;
- `TasksMax=`;
- bounded restart policy.

However, netd currently owns one intentionally narrow kernel tunable write:

```text
/proc/sys/net/ipv4/ip_forward
```

A service profile that blindly enables `ProtectKernelTunables=yes` would contradict that runtime requirement. Phase 9 defines and qualifies the service-hardening contract; Phase 10 owns the actual unit files and must not claim a directive that breaks forwarding control.

### 2.3 Eggstack diagnostics

Eggprobe is a useful generic network diagnostic tool, but its current owned primitives are DNS/TCP/TLS/HTTP/route evidence. Phase 9 doctor requirements are primarily wg-basic-local authority:

- state schema/integrity;
- path ownership;
- installation/generation;
- netd authorization/capability;
- WireGuard/nftables support;
- ownership drift;
- forwarding state;
- management service readiness.

No Eggprobe runtime dependency is selected.

Operators may still use Eggprobe externally for general path/connectivity diagnostics.

### 2.4 Upgrade substrate

Eggup remains the preferred Phase 10 local binary replacement substrate.

Phase 9 must define the state side of that transaction first. An older wg-basic correctly refuses a database with a newer schema, so rollback after a schema migration cannot mean “put the old executable back” only.

A safe rollback transaction requires both:

- previous binary;
- pre-upgrade state snapshot compatible with that binary.

## 3. Decision: doctor is authoritative and read-only

`wg-basic doctor` becomes a typed local diagnostic aggregator.

It MUST NOT repair or mutate by default.

It produces:

- concise human output;
- stable JSON output via `--json`;
- per-check identifier;
- pass/warn/fail disposition;
- bounded safe evidence;
- actionable remediation;
- aggregate exit status.

Checks derive from existing typed backends/state APIs rather than shell parsing where wg-basic already owns a direct API.

Doctor may contact netd only through typed read/plan operations.

No doctor check may apply network intent.

## 4. Decision: diagnostic scope

The Phase 9 baseline includes checks for:

### Runtime/platform

- Linux architecture/kernel release;
- bundled SQLite runtime/source version;
- process effective UID/GID;
- netd reachability;
- CAP_NET_ADMIN state as observed by netd;
- runtime socket-directory safety.

### State

- state path presence/type/owner/mode;
- schema supported/current;
- quick/integrity and foreign-key check;
- installation identity/generation;
- convergence status;
- service singleton lock state;
- automatic recovery artifacts present.

### Network

- WireGuard Generic Netlink usable;
- RTNETLINK usable;
- nftables executable/backend usable;
- IPv4 forwarding current value;
- desired interface ownership/tag;
- desired nftables table ownership;
- plan-only drift/conflict result;
- configured listen-port conflict where it can be proven safely.

### HTTP configuration

When HTTP bind/origin options are supplied, doctor validates the same `ServeConfig` policy without opening a listener.

Unknown/indeterminate is a first-class diagnostic outcome where the host cannot prove a fact read-only.

## 5. Decision: service singleton / maintenance lease

SQLite's own locking protects transactions, but it does not express the product rule “only one wg-basic management service owns this database.”

Phase 9 adds a process-level service lease beside the state database.

Requirements:

- one live `serve` process per state database;
- kernel advisory lock, not PID-file trust;
- crash/SIGKILL automatically releases the lock;
- symlink/path ownership protections match state-path policy;
- a second serve fails immediately and clearly.

Offline destructive maintenance operations require the service lease to be free.

Read-only status/doctor and online backup remain permitted while serve is running unless the operation itself requires exclusivity.

## 6. Decision: durable network enabled state

Phase 9 adds a durable server/network operational-enabled flag.

Disabling the network:

- preserves installation identity;
- preserves server/client keys and metadata;
- preserves address assignments;
- advances DesiredGeneration;
- projects the managed interface absent;
- projects managed firewall policy absent;
- reconciles firewall removal before interface teardown using existing contracts;
- remains disabled across serve/netd/host restart.

Enabling reverses projection and reconstructs the same owned network state.

This is distinct from disabling an individual client.

## 7. Decision: operator network control

Phase 9 provides explicit local operator commands:

```text
wg-basic network status
wg-basic network disable
wg-basic network enable
```

The mutating forms are offline maintenance commands: they require the management service lease to be free and use the same generation-safe product/runtime services rather than editing SQL directly.

They may contact netd through the typed protocol to enforce the committed state.

No root escalation is attempted internally.

A future UI may expose the same product operation through the authenticated worker, but Phase 9 does not require that UX.

## 8. Decision: purge semantics

`state purge` is destructive state removal, not a synonym for network disable or uninstall.

Purge requires:

1. service lease free;
2. state database validates;
3. caller supplies the exact InstallationId as confirmation;
4. durable network operational state is disabled;
5. disabled generation is recorded converged;
6. a fresh plan-only netd observation confirms no wg-basic-owned network mutation remains to apply.

If netd cannot prove absence, purge fails closed.

Purge removes only wg-basic's live state database and known automatic sidecars/recovery artifacts under the same owned state path.

It does not remove arbitrary operator-created backups elsewhere.

It does not uninstall the binary or service units; Phase 10 owns uninstall.

A `--dry-run` prints exactly what would be removed and every unmet precondition.

No “force orphan owned kernel state and delete the database anyway” path is in the Phase 9 baseline.

## 9. Decision: backup/restore operational UX

Keep SQLite online backup and offline restore as the underlying mechanisms.

Add an explicit non-mutating backup verification command, conceptually:

```text
wg-basic state verify <backup>
```

It reports safe metadata, integrity, schema compatibility, and whether migration would be required.

Backup creation SHOULD validate the completed destination before reporting success.

Restore remains offline/exclusive and must additionally prove the service lease is free.

Phase 9 adds repeatable recovery drills rather than another storage format.

## 10. Decision: structured application logging

Long-running roles log to stderr only.

The binary does not implement log files, rotation, or retention. Those belong to journald/service-manager/operator policy.

Introduce a small project-owned structured event model rather than a general logging framework unless implementation evidence requires one.

Required fields include where applicable:

- stable event code;
- role;
- severity;
- operation/action;
- resource kind/stable ID;
- desired generation;
- stage: planned/applied/verified or before/after mutation;
- bounded outcome category.

Support:

- concise human format;
- newline-delimited JSON format for operators/service managers.

Never log:

- passwords/verifiers;
- session/CSRF/enrollment bearer tokens;
- private/preshared keys;
- generated configs;
- raw HTTP bodies;
- raw protocol payloads;
- backend errors that embed secrets.

CLI result output remains stdout; operational logs remain stderr.

## 11. Decision: retention and housekeeping

Application logs are not retained in SQLite.

Phase 9 defines bounded housekeeping for durable operational/security rows that can otherwise grow without limit:

- expired/revoked sessions;
- consumed/expired/revoked enrollment capabilities;
- audit history.

Retention must be deterministic and documented.

Audit pruning preserves recent bounded history and does not rewrite desired configuration.

Housekeeping is an application-state operation and MUST NOT advance DesiredGeneration.

Exact limits belong to the owning implementation plan and must be justified against expected appliance scale.

## 12. Decision: crash/restart hardening

Phase 9 qualifies crash behavior beyond the functional restart tests already closed.

Required scenarios include:

- SIGKILL serve while idle and during safe reads;
- SIGKILL serve after durable mutation commit but before HTTP response;
- SIGKILL netd during privileged apply;
- immediate serve restart against released service lease;
- immediate netd restart against stale owned socket;
- repeated crash/restart cycles without stale lock/socket accumulation;
- restart while durable network is disabled.

No daemon self-fork/backgrounding is introduced.

Phase 10 service-manager restart policy will consume these semantics.

## 13. Decision: resource hardening contract

The binary keeps its existing explicit HTTP bounds.

Phase 9 additionally qualifies:

- netd frame limit, one-request-per-connection model, 2-second I/O deadline, backlog bound;
- bounded worker queue;
- bounded login/enrollment limiter cardinality;
- session/enrollment/audit housekeeping;
- no file descriptor/thread growth under repeated malformed/slow requests;
- memory/CPU behavior under representative abuse.

Phase 9 publishes recommended service-manager ceilings but does not ship systemd units yet.

Do not select a MemoryMax below measured normal/Argon2 peak behavior.

## 14. Decision: Phase 10 service profile handoff

Phase 9 produces an explicit systemd hardening contract for Phase 10.

Management role target:

- dedicated unprivileged user;
- no capabilities;
- `NoNewPrivileges=yes`;
- read/write only its state/runtime needs;
- loopback HTTP by default;
- address families limited to AF_UNIX + required IP listener families;
- core dumps disabled by unit policy;
- bounded tasks/memory;
- restart-on-failure with rate-limited restart.

netd target:

- dedicated identity where feasible;
- only CAP_NET_ADMIN in the capability bounding/ambient set;
- AF_UNIX + AF_NETLINK and only other proven required families;
- no shell;
- no home access;
- filesystem mostly read-only;
- write access limited to runtime socket and the explicitly required forwarding sysctl semantics.

The netd profile must record why `ProtectKernelTunables=yes` cannot be asserted while netd directly owns `ip_forward`.

Phase 10 owns concrete unit syntax, installation identities, directories, and compatibility fallbacks.

## 15. Decision: security and abuse qualification

Phase 9 performs a focused pre-release security review of:

- privileged UDS framing/auth/version/timeout/backlog;
- HTTP Host/Origin/CSRF/session/cookie perimeter;
- login and enrollment brute-force resistance;
- one-time enrollment replay;
- request/header/body/connection exhaustion;
- product generation race/conflict handling;
- secret handling in logs/audit/errors/process arguments;
- nft subprocess containment and fixed argv/stdin construction;
- owner-tag/firewall preservation;
- dependency/security-advisory state.

Add a pinned/reproducible RustSec/cargo-audit gate if it can run reliably in CI without changing runtime dependencies.

No “security review complete” claim is allowed with unresolved high/medium findings.

## 16. Decision: upgrade and rollback rehearsal

Phase 9 closes only after a real old→new schema rehearsal.

The Phase 8 closure commit `e8fd6b1` is the initial old-binary baseline.

A Phase 9 schema change (durable network-enabled state) provides a real newer schema.

Rehearsal must prove:

1. old binary creates/uses a schema-v4 installation;
2. secret-bearing pre-update backup is taken;
3. new binary migrates it and preserves product semantics;
4. new binary starts/reconciles/serves correctly;
5. old binary refuses the newer schema;
6. rollback restores the pre-update state snapshot before relaunching old binary;
7. old binary then opens and serves the restored state;
8. new binary can upgrade it again.

This becomes a normative Phase 10 updater invariant.

## 17. Consequences

Positive:

- operators get actionable diagnostics before installation automation exists;
- disable and purge become unambiguous and safe;
- duplicate management service ownership is prevented;
- logging is useful without becoming a secret-bearing second database;
- operational row growth is bounded;
- crash behavior is qualified rather than assumed;
- Phase 10 receives a precise service/update contract.

Costs:

- schema v5 is introduced for server operational state;
- operational CLI gains maintenance semantics;
- real old/new binary CI rehearsal is more expensive;
- structured event logging touches both process roles;
- service-manager hardening remains a two-phase contract: specified now, installed later.

## 18. Verification consequences

Phase 9 must preserve every Phase 6–8 rootful/product/security suite and add:

- doctor integration;
- network disable/re-enable persistence;
- purge fail-closed matrix;
- service lease crash/restart tests;
- backup verification/recovery drill;
- structured-log secret scans;
- HTTP/UDS abuse soak;
- dependency advisory gate;
- old/new schema migration and rollback rehearsal.
