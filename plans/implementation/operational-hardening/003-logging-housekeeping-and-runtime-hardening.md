# Operational Hardening M003 — Structured Logging, Housekeeping, and Runtime Hardening

Status: closed

Source roadmap:

- `plans/subsystems/operational-hardening-roadmap.md#7-m003--structured-logging-housekeeping-crash-and-resource-hardening`

Canonical architecture:

- `plans/adr/005-operational-hardening-maintenance-and-recovery.md`

Primary class: operations / observability / resilience

Hard dependency: Operational Hardening M002 strict closure.

## 1. Objective

Make serve/netd diagnosable and bounded during long-running operation without creating a second secret-bearing state/logging subsystem.

M003 also produces the concrete service-manager hardening contract Phase 10 must install.

## 2. Structured event model

Create a small project-owned operational event module.

Required fields where applicable:

- event code;
- severity;
- process role;
- operation/action;
- stable resource kind/ID;
- desired generation;
- reconcile stage;
- bounded outcome category;
- timestamp.

Do not expose arbitrary backend error strings as event fields.

Suggested stable event codes include:

- `serve.started`;
- `serve.degraded`;
- `serve.stopping`;
- `netd.started`;
- `netd.request_rejected`;
- `reconcile.started`;
- `reconcile.completed`;
- `reconcile.degraded`;
- `state.backup_completed`;
- `state.restore_completed`;
- `network.disabled`;
- `network.enabled`;
- `doctor.completed`;
- `security.rate_limited`.

Do not log every health/telemetry poll.

## 3. Output formats

Support long-running roles with:

- concise human stderr;
- newline-delimited JSON stderr.

A flag such as `--log-format human|json` may be role-local or global if it does not destabilize existing CLI parsing.

Rules:

- command result/output stays stdout;
- operational events stay stderr;
- one JSON event per line;
- no ANSI escape in JSON;
- no filesystem log target;
- no built-in log rotation.

Journald/service-manager retention remains outside the binary.

Avoid adding `tracing`/a general framework unless implementation evidence shows the project-owned event model is inadequate.

## 4. Secret-redaction invariant

Operational events MUST NOT contain:

- passwords or PHC verifiers;
- session bearer/CSRF tokens;
- enrollment tokens;
- private/preshared keys;
- generated configs;
- QR payload/config;
- raw HTTP bodies;
- raw privileged-protocol frames;
- SQL text with bound values.

Add compile/static/runtime fixture scans over representative logs.

Stable non-secret IDs, client labels after control-character validation, generation numbers, and bounded outcome categories may be logged.

## 5. Session housekeeping

Current persistent sessions must not grow forever.

Initial policy:

- prune expired sessions at serve startup and before successful session issuance;
- maximum 32 live sessions for the local administrator;
- when issuing session 33, revoke/prune the oldest live session after expired rows are removed;
- password reset continues revoking all sessions.

Housekeeping does not alter DesiredGeneration.

Test restart and concurrency behavior.

## 6. Enrollment housekeeping

Initial policy:

- maximum 8 live unconsumed/unrevoked enrollment capabilities per client;
- prune terminal capability rows (consumed, revoked, or expired) older than 7 days;
- run pruning on serve startup and before capability creation;
- audit events preserve the durable security history after capability rows are removed.

No token secret is involved in pruning.

## 7. Audit retention

Bound application audit growth.

Initial policy:

- retain newest 10,000 audit events;
- after insertion would exceed the bound, delete oldest rows deterministically by timestamp + event ID;
- product mutation + its new audit row remains atomic;
- pruning must never delete the event being written;
- retention transaction does not independently advance DesiredGeneration.

Document that this is product audit history, not system log retention.

Qualify pagination correctly across pruning boundaries.

## 8. Crash/restart qualification

Add process-level cases:

### serve

- SIGKILL while idle;
- SIGKILL after DB/product commit before HTTP reply;
- immediate restart obtains released lease;
- session/state integrity remains;
- no stale worker/thread ownership artifact.

### netd

- SIGKILL while idle;
- SIGKILL during/in between aggregate layers using existing deterministic fixture seam;
- immediate restart safely removes only its stale owned socket;
- startup reconciliation converges durable generation.

### disabled network

- crash/restart both roles while operationally disabled;
- no interface/firewall resurrection until explicit enable.

Run repeated bounded cycles (for example 20) to catch descriptor/socket/lock leaks without making CI a soak test.

## 9. Resource stability qualification

Measure before/after bounded stress:

- open file descriptors;
- thread/task count;
- RSS;
- state DB row counts for sessions/enrollment/audit.

Exercise:

- repeated ordinary HTTP requests;
- rejected Host/Origin/CSRF requests;
- login throttling;
- enrollment replay failures;
- malformed/timeout netd connections.

Acceptance uses bounded growth/no monotonic leak, not exact machine-independent RSS timing.

## 10. Existing HTTP bounds

Re-run and pin the current published limits.

Tests at exactly/beyond:

- connection ceiling;
- header count/bytes;
- target bytes;
- body bytes;
- header/body/handler/write deadlines;
- keepalive lifetime;
- max requests per connection.

Do not change limits just to make a stress fixture convenient.

Any change requires measured justification and docs update.

## 11. Existing netd bounds

Pin and stress:

- `MAX_FRAME_SIZE = 64 KiB`;
- 2-second read/write timeout;
- backlog 16;
- one request per connection;
- peer credentials before payload parse;
- one accepted request processed at a time.

Measure the maximum denial window of an authorized slow peer and record it honestly.

Do not add concurrency to privileged mutation merely for throughput.

## 12. Phase 10 systemd hardening contract

Create:

- `architecture/service-hardening.md`.

It must contain a table for `serve` and `netd`.

### serve target

At least:

- dedicated unprivileged account;
- no ambient/bounding capabilities;
- `NoNewPrivileges=yes`;
- `ProtectSystem=strict` or strongest compatible setting;
- `ProtectHome=yes`;
- `PrivateTmp=yes`;
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`;
- state/runtime paths explicitly writable;
- `LimitCORE=0`;
- bounded `TasksMax` and `MemoryMax` chosen above measured normal/Argon2 peaks;
- `Restart=on-failure` with bounded restart delay/start-rate policy.

### netd target

At least:

- only `CAP_NET_ADMIN` unless evidence proves another capability;
- `NoNewPrivileges=yes`;
- no home access;
- private tmp;
- root filesystem read-only except explicit required paths;
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` plus any additional family proven necessary;
- core dumps disabled;
- bounded tasks/memory;
- bounded restart policy.

Document the direct `/proc/sys/net/ipv4/ip_forward` write.

Do not claim `ProtectKernelTunables=yes` while that write remains runtime-owned by netd.

Phase 10 may revise the profile only with implementation evidence.

## 13. Recommended resource ceilings

Measure first, then select ceilings with explicit headroom.

Do not set `MemoryMax` close to the ~13.5 MiB idle RSS: Argon2 alone intentionally uses ~19 MiB plus process overhead.

Closure should recommend conservative initial service limits rather than optimize for the smallest possible cgroup.

## 14. Tests

Add:

- human/JSON event snapshots;
- secret corpus never appears in logs;
- stdout/stderr separation;
- housekeeping bounds and no DesiredGeneration change;
- audit pruning/pagination;
- process crash/restart cycles;
- FD/thread/RSS bounded-growth evidence;
- existing HTTP/netd boundary stress;
- systemd-contract static consistency against actual runtime needs.

## 15. Acceptance criteria

M003 closes only when:

1. serve/netd emit useful structured secret-safe operational events;
2. JSON logging is machine-parseable and line-delimited;
3. the binary owns no log files/rotation;
4. sessions/enrollment/audit have documented bounded retention;
5. housekeeping does not alter desired configuration generation;
6. repeated crash/restart leaves no stale trusted lease/socket;
7. no descriptor/thread/row-count leak appears in bounded stress;
8. service-hardening contract is explicit and does not contradict `ip_forward`;
9. all prior Phase 6–8 CI/MSRV/rootful tests remain green.

## 16. Stop conditions

Stop/ADR if structured logging requires a framework that materially changes footprint, housekeeping risks deleting authoritative configuration, resource ceilings cannot accommodate Argon2/product traffic, or a proposed systemd directive breaks a required runtime operation.

## 17. Closure evidence

Record event schema/examples, secret scan, retention limits, crash-cycle evidence, resource measurements, netd authorized-slow-peer bound, recommended systemd ceilings/directives, dependency diff, CI/MSRV, and M004 readiness.
