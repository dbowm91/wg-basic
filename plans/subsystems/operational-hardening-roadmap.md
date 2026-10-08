# Operational Hardening Roadmap

Status: active; M001–M004 closed, M005 active

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

Predecessor state:

- Phase 8 is strictly closed at `e8fd6b1`;
- current-head CI is green across ordinary Rust plus all rootful suites.

## 1. Purpose

Phase 9 hardens the complete product for unattended Linux operation before Phase 10 installs and updates it automatically.

It owns:

- authoritative read-only diagnostics;
- process/service ownership and maintenance exclusion;
- explicit network disable/re-enable semantics;
- destructive purge preconditions;
- backup verification and recovery drills;
- structured secret-safe operational logs;
- retention/housekeeping of operational rows;
- crash/restart qualification;
- service-manager hardening requirements;
- HTTP/IPC abuse and resource qualification;
- privileged-boundary/secret-handling review;
- dependency advisory checks;
- real schema upgrade/rollback rehearsal.

It does not own:

- release artifact publication;
- installer scripts;
- systemd unit installation;
- Eggup/Eggpack integration;
- direct TLS/ACME;
- IPv6 production support.

## 2. Core invariants

1. Doctor is read-only by default.
2. Operational diagnosis never silently repairs host state.
3. Only one live management service owns one state database.
4. SIGKILL cannot leave a trusted-but-stale service lease.
5. Network disable preserves durable configuration and remains disabled across restart.
6. Purge cannot delete the authority database while owned network state may still exist.
7. Purge never deletes arbitrary operator backups.
8. Backup verification does not modify the backup.
9. Operational logging never contains credential/config secrets.
10. Long-running roles log to stderr; ordinary command output remains stdout.
11. Logs are not retained in SQLite.
12. Housekeeping does not advance DesiredGeneration.
13. Abuse tests must prove bounds, not runner speed.
14. Phase 9 service-manager recommendations may not contradict real runtime needs.
15. Binary rollback after schema migration requires rollback of the database to a compatible snapshot.
16. All Phase 6–8 security/network/product invariants remain green.

## 3. Current-state research

### 3.1 Doctor today

Current `wg-basic doctor` only requests `InspectCapabilities` from netd and prints the resulting snapshot.

That snapshot is useful but incomplete for the now-shipped appliance. It does not aggregate:

- state integrity/schema;
- SQLite runtime version;
- convergence;
- product configuration;
- owner drift;
- HTTP bind/origin validity;
- service singleton state;
- recovery artifacts;
- actionable remediation.

### 3.2 State and recovery today

Current state operations already provide:

- online SQLite backup;
- candidate validation;
- offline restore;
- pre-migration recovery snapshot;
- schema-newer-than-binary refusal;
- startup reconciliation after restore.

The remaining operational gap is coordinated use:

- prove backup usability without replacing live state;
- prevent restore/purge while serve still owns the state;
- distinguish “stop networking but keep configuration” from “destroy state”.

### 3.3 Process ownership today

netd already gets singleton behavior from safe Unix-socket ownership and stale-socket handling.

serve has no equivalent process-level singleton lease for one database.

SQLite transaction locking prevents corrupt writes but is not the same product invariant.

### 3.4 SQLite runtime

Current locked `libsqlite3-sys` 0.38.2 bundles SQLite 3.53.2.

The WAL-reset corruption bug affected WAL databases through 3.51.2 and was fixed in 3.51.3. The current bundled runtime is therefore beyond the known affected versions.

Doctor and closure evidence should report the actual SQLite runtime/source ID rather than assuming dependency intent equals runtime fact.

### 3.5 Runtime bounds today

HTTP already has explicit bounds:

- 64 connections;
- 128 in-flight requests;
- 32 headers / 8 KiB aggregate;
- 1 KiB target;
- 16 KiB body;
- independent header/body/handler/write/idle/connection deadlines;
- 256 requests per connection.

netd already has:

- 64 KiB frame ceiling;
- 2-second per-connection read/write timeout;
- backlog 16;
- one request served at a time;
- peer credentials checked before request parsing.

Phase 9 should qualify these under hostile workloads rather than inventing a second limiter layer without evidence.

## 4. Dependency graph

```text
Phase 8 closed
     |
     v
M001 — authoritative doctor + preflight
     |
     v
M002 — maintenance lease + network disable/purge + recovery UX
     |
     v
M003 — structured logs + housekeeping + crash/resource/service hardening contract
     |
     v
M004 — abuse/security qualification + dependency review
     |
     v
M005 — old/new upgrade + state rollback rehearsal + Phase 9 closure
```

All implementation dependencies are hard.

## 5. M001 — Authoritative doctor and preflight

Status: closed.

Implementation plan:

- `plans/implementation/operational-hardening/001-authoritative-doctor-and-preflight.md`

Objective:

Turn doctor into a read-only operator diagnostic report spanning the actual product.

Expected outcomes:

- typed diagnostic result model;
- human + JSON rendering;
- pass/warn/fail/unknown states;
- state/schema/integrity checks;
- SQLite runtime/source identity;
- netd reachability/capability;
- WireGuard/RTNETLINK/nftables read-only probes;
- forwarding state;
- plan-only ownership/drift check;
- service-lock state;
- HTTP bind/origin validation;
- safe listen-port conflict evidence where provable;
- actionable remediation and stable exit codes.

No repair mode.

## 6. M002 — Operational state lifecycle and recovery UX

Status: closed; M001 and M002 are strictly closed.

Implementation plan:

- `plans/implementation/operational-hardening/002-maintenance-disable-purge-and-recovery.md`

Objective:

Make maintenance semantics safe and explicit.

Expected outcomes:

- one serve process per state DB through advisory service lease;
- real schema v5 durable network-enabled state;
- offline `network status/disable/enable`;
- disable survives restart and removes owned network state;
- enable restores the same server/client state;
- `state verify <backup>`;
- backup self-validation before success;
- restore requires service lease free;
- `state purge --dry-run`;
- purge requires InstallationId confirmation, disabled+converged state, and fresh plan proving no owned resources remain;
- purge removes only known wg-basic state/recovery artifacts.

## 7. M003 — Structured logging, housekeeping, crash and resource hardening

Status: closed; strict closure recorded at `plans/closure/operational-hardening/003-status.md`.

Implementation plan:

- `plans/implementation/operational-hardening/003-logging-housekeeping-and-runtime-hardening.md`

Objective:

Make long-running behavior diagnosable and bounded under months of operation and repeated process failure.

Expected outcomes:

- project-owned structured operational event model;
- text and NDJSON stderr formats;
- secret-safe event taxonomy;
- session/enrollment/audit housekeeping policy;
- crash/restart stress against serve/netd/service lease/socket cleanup;
- FD/thread/memory stability checks;
- existing HTTP/netd bounds stress-qualified;
- Phase 10 systemd hardening contract documented;
- no log-file/rotation implementation in the binary.

## 8. M004 — Abuse and security qualification

Status: closed; strict closure recorded at `plans/closure/operational-hardening/004-status.md`.

Implementation plan:

- `plans/implementation/operational-hardening/004-abuse-security-and-dependency-qualification.md`

Objective:

Run the pre-release adversarial review over the complete Phase 8 product.

Expected outcomes:

- malformed/oversized/truncated/slow UDS frame flood;
- unauthorized local-peer flood;
- HTTP slowloris/header/body/connection churn;
- login/enrollment brute-force qualification;
- session/enrollment churn;
- generation-race/stale-writer stress;
- owner-tag/firewall preservation under rejected inputs;
- secret scans across logs/audit/errors/HTTP/argv;
- nft subprocess review;
- dependency tree/advisory gate;
- no unresolved high/medium finding.

## 9. M005 — Upgrade/rollback rehearsal and Phase 9 closure

Status: active; M004 is strictly closed.

Implementation plan:

- `plans/implementation/operational-hardening/005-upgrade-rollback-rehearsal-and-phase9-closure.md`

Objective:

Prove the operational upgrade contract Phase 10 must automate.

Expected outcomes:

- build/run Phase 8 closure baseline `e8fd6b1` as old binary;
- create real schema-v4 product state;
- take secret-bearing pre-update backup;
- current binary performs real v4→v5 migration;
- product/session/config semantics survive;
- current candidate reconciles and passes traffic;
- old binary refuses schema v5;
- restore pre-update v4 snapshot;
- old binary works again;
- new binary can re-upgrade and work again;
- failed-candidate rollback ordering documented for Eggup/Phase 10;
- all prior product/security/rootful suites green;
- Phase 9 closure record and Phase 10 readiness recommendation.

## 10. Doctor result model

Suggested internal/public CLI representation:

```text
DoctorReport {
    version,
    generated_at,
    overall,
    checks: [
        DoctorCheck {
            id,
            disposition,
            summary,
            evidence,
            remediation
        }
    ]
}
```

Dispositions:

- pass;
- warn;
- fail;
- unknown.

Evidence and remediation strings are bounded and secret-safe.

JSON schema stability is desirable for operator automation, but Phase 9 need not publish a long-term compatibility guarantee beyond the current major product version.

## 11. Doctor exit codes

Recommended:

- 0: all required checks pass; warnings may be present only if explicitly classified non-blocking;
- 1: one or more warnings/unknowns requiring operator attention but appliance may run;
- 2: one or more failed required checks or invalid invocation.

Keep invocation/parser failures distinguishable from diagnostic outcome in human text even if they share process code 2.

## 12. Read-only backend probing

Doctor should prefer direct existing APIs:

- Generic Netlink family resolution / WireGuard observation;
- RTNETLINK observation;
- bounded `nft --version` and read-only table/list probe in the existing nft process boundary;
- `/proc/sys/net/ipv4/ip_forward` read;
- aggregate plan-only reconcile for desired ownership/drift.

Do not add “repair” to `InspectCapabilities`.

If a check would require mutation to know the answer, report unknown/warn and explain the limitation.

## 13. Service lease direction

Use an advisory file lock adjacent to or inside the state directory.

The lease artifact is not proof of process identity by contents; the kernel-held lock is authoritative.

The file may contain safe diagnostics such as PID/start time, but stale contents are informational only.

Serve:

- acquires non-blocking exclusive lease before owning StateStore;
- holds it until shutdown/drop.

Offline destructive commands:

- require lease acquisition before mutation/replacement/purge.

Read-only doctor/status and online backup do not need exclusive maintenance ownership.

## 14. Durable network-enabled state

Schema v5 should prefer a single explicit boolean on the primary interface/product settings rather than rewriting interface/client records.

Migration v4→v5 backfills enabled=true.

Projection when disabled:

- desired managed interface lifecycle absent;
- network policy absent;
- product/client records unchanged.

The same desired generation still controls both persistence and enforcement.

## 15. Purge ownership contract

Before deleting state, compute the disabled desired intent and ask netd for a plan only.

Purge proceeds only if:

- no interface/firewall mutation is needed;
- no ownership conflict exists;
- current desired generation equals last converged generation.

Known automatic artifacts eligible for removal may include:

- live DB;
- WAL/SHM sidecars;
- deterministic pre-migration snapshots;
- deterministic pre-restore retained DB;
- service lease file after lock release.

Do not glob unrelated files.

Print exact paths in dry-run and final receipt.

## 16. Logging event direction

Example event codes:

```text
serve.started
serve.degraded
serve.stopping
netd.started
netd.request_rejected
reconcile.started
reconcile.completed
reconcile.degraded
state.backup_completed
state.restore_completed
network.disabled
network.enabled
doctor.completed
security.rate_limited
```

Do not log every successful telemetry poll or health request by default.

Stable IDs/generations may be logged; secrets may not.

## 17. Housekeeping direction

Initial policy candidates to qualify:

- delete expired sessions promptly and cap live sessions per principal;
- delete consumed/revoked/expired enrollment capability rows after a bounded retention window;
- retain a bounded recent audit history by row count and/or age.

Audit retention must preserve enough history for operator/security troubleshooting.

Any automatic pruning transaction is independent of DesiredGeneration.

## 18. Service-manager hardening handoff

M003 must produce a Phase 10-consumable table of:

### serve

- user/group;
- capabilities: none;
- writable paths;
- address families;
- task/memory bounds;
- core dump policy;
- restart policy;
- network exposure assumptions.

### netd

- user/group;
- CAP_NET_ADMIN only unless evidence proves otherwise;
- writable runtime path;
- required address families;
- nft binary execution requirement;
- direct `ip_forward` write requirement;
- incompatible hardening directives clearly marked.

This is contract evidence, not installed units.

## 19. Abuse qualification scale

Stress sizes should be representative and bounded so CI remains deterministic.

Examples:

- thousands of malformed UDS frames/connections;
- HTTP connection churn up to and beyond configured ceiling;
- headers/body exactly at and just over limits;
- login attempts beyond global/per-peer budgets;
- repeated invalid enrollment tokens;
- thousands of audit rows with bounded page queries;
- hundreds/thousands of client telemetry mappings without unbounded response construction.

Use deterministic clocks/fixtures where rate limits are involved.

## 20. Dependency/security review

At M004:

- `cargo tree --locked`;
- RustSec/cargo-audit with a pinned CI tool version or equivalent reproducible advisory check;
- review direct native/process boundaries;
- confirm bundled SQLite runtime >= 3.51.3;
- review advisories affecting direct dependencies and their actual enabled features.

An advisory may be dispositioned rather than blindly upgraded if proven unreachable/not applicable, but the rationale belongs in closure evidence.

## 21. Upgrade rehearsal contract

The upgrade test should treat the database and executable as one compatibility transaction:

```text
old binary + old DB
   -> backup old DB
   -> install/start new binary
   -> new binary migrates DB
   -> health/product validation
       success -> commit update
       failure -> stop new binary
                  restore old DB snapshot
                  restore old binary
                  start/validate old version
```

Never start the old binary against a migrated newer DB and call its fail-closed refusal a successful rollback.

## 22. Milestone status

| Milestone | Status | Implementation plan | Hard blocker |
|---|---|---|---|
| M001 authoritative doctor/preflight | closed | `plans/implementation/operational-hardening/001-authoritative-doctor-and-preflight.md` | closure: `plans/closure/operational-hardening/001-status.md` |
| M002 maintenance/disable/purge/recovery | closed | `plans/implementation/operational-hardening/002-maintenance-disable-purge-and-recovery.md` | closure: `plans/closure/operational-hardening/002-status.md` |
| M003 logging/housekeeping/runtime hardening | closed | `plans/implementation/operational-hardening/003-logging-housekeeping-and-runtime-hardening.md` | closure: `plans/closure/operational-hardening/003-status.md` |
| M004 abuse/security/dependency qualification | closed | `plans/implementation/operational-hardening/004-abuse-security-and-dependency-qualification.md` | closure: `plans/closure/operational-hardening/004-status.md` |
| M005 upgrade/rollback rehearsal/closure | active | `plans/implementation/operational-hardening/005-upgrade-rollback-rehearsal-and-phase9-closure.md` | M004 strictly closed |
