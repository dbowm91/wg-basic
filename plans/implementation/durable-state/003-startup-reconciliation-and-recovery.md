# Durable State M003 — Startup Reconciliation and Crash/Restart Recovery

Status: blocked on Durable State M002 closure

Source roadmap:

- `plans/subsystems/durable-state-restart-reconciliation-roadmap.md#8-milestone-m003--startup-reconciliation-and-crashrestart-recovery`

Canonical requirements:

- `plans/adr/002-durable-state-generations-and-ownership.md`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/000-long-term-specification.md#12-durable-storage`

Primary class: capability / invariant

Hard dependency:

- Durable State M002 strictly closed.

## 1. Objective

Make the management role recover desired network state automatically from SQLite after process restart, netd restart, and partial prior application.

After M003, durable configuration must be sufficient to reconstruct the managed network substrate without manually resubmitting configuration.

## 2. Management runtime ownership

The management role becomes the owner of:

- StateStore lifetime;
- current desired generation;
- state projection;
- aggregate netd reconcile requests;
- convergence evidence update.

It still does not host HTTP in M003.

The current `serve` command may evolve from a one-shot ping into a management runtime or a new internal/service command may be introduced if that makes lifecycle clearer.

Do not freeze final install/service CLI solely for this milestone.

## 3. Startup sequence

Canonical startup:

1. validate state directory/database path;
2. open hardened store;
3. run/verify migrations;
4. load current desired snapshot + generation;
5. validate/project to `InstallationNetworkIntent`;
6. connect to authorized netd;
7. submit aggregate apply for current generation;
8. receive/validate same-generation receipt;
9. conditionally record convergence evidence if the database still has that generation;
10. enter idle service state or exit according to the current command role.

Startup MUST reconcile even if `last_converged_generation == desired_generation`.

## 4. Convergence evidence API

Extend M001 state API with conditional methods such as:

- `record_attempt_start(generation)`;
- `record_attempt_result(generation, disposition)`;
- `record_converged_if_current(generation)`.

All updates are conditioned on the intended generation where needed.

An old apply completion MUST NOT advance `last_converged_generation` past or equal to a newer current desired state incorrectly.

If current desired generation is N+1 and a receipt for N arrives, store it only as stale attempt evidence if useful; it cannot mark current convergence.

## 5. Mutation-to-reconcile coordinator

Create one management-side coordinator used by both startup and future Phase 7 mutations.

Conceptually:

```text
commit desired state N
        |
        v
enqueue/coalesce current generation
        |
        v
apply current N through netd
        |
        v
record result if N still current
```

M003 does not need a general scheduler.

Requirements:

- bounded queue/state;
- no unbounded per-write reconcile tasks;
- if several writes occur before an apply begins, it may coalesce to the latest generation;
- once an apply begins, a newer generation may wait;
- after completion, if store generation advanced, immediately reconcile the latest state;
- shutdown/cancellation leaves DB desired state intact and recoverable.

## 6. Retry semantics

Do not spin indefinitely on persistent conflicts.

Classify:

### Retryable immediately/bounded

- netd unavailable during startup;
- transient IPC disconnect;
- partial apply where fresh retry is expected to converge.

### Non-retryable without operator/state change

- foreign owner tag;
- wrong-kind interface;
- foreign nft table;
- invalid/corrupt desired state;
- unsupported backend.

Initial policy should use a small bounded retry/backoff for transient failures, then surface service health failure while preserving desired state.

A later service manager can restart the process.

Do not add a permanent high-frequency reconciliation loop.

## 7. Crash-point qualification

Build deterministic tests for these points.

### A. Commit before apply

1. generation N commits;
2. simulate management crash before netd call;
3. restart management;
4. startup loads N and converges it.

### B. Partial netd apply

1. N committed;
2. inject failure after interface mutation/before firewall completion;
3. management/netd restarts;
4. startup re-observes and equal-generation retry completes.

### C. Converged kernel before DB receipt update

1. N applies completely;
2. simulate management crash before convergence evidence commit;
3. restart;
4. idempotent startup reapply returns NoChange;
5. convergence evidence becomes N.

### D. Newer generation during older apply

1. N apply starts;
2. state advances to N+1;
3. N completes;
4. N receipt cannot mark N+1 converged;
5. coordinator applies N+1.

## 8. Kernel drift while stopped

Required rootful scenarios:

- owned tagged WireGuard link deleted while services stopped -> startup recreates/reconfigures;
- owned link exists but peer/address/route drifted -> startup repairs;
- owned nft table deleted -> startup recreates;
- owned nft expression drift -> startup replaces;
- link owner tag removed/changed -> startup fails closed rather than re-adopting;
- nft owner marker changed -> startup fails closed.

## 9. Secret handling during startup

- desired snapshot Debug remains redacted;
- reconcile errors stored as categories, not secret-bearing strings;
- do not dump the full persisted snapshot on startup failure;
- never place private keys in logs, process titles, environment, or temp files.

## 10. Netd availability

Management startup may need netd to be started first by the future service manager.

M003 should support:

- clear “netd unavailable” health/error state;
- bounded connection retry;
- no fallback to privileged local mutation inside management process.

Do not auto-spawn netd with sudo/root from the management role.

## 11. State mutation test API

To exercise concurrent-generation semantics before HTTP exists, add a small internal/test command surface or direct integration harness.

Do not prematurely build the public administration CLI if that would freeze Phase 7 API semantics.

## 12. Reconcile-on-write

After startup coordinator exists, a committed desired-state mutation through the management API should trigger reconciliation automatically in process.

A database transaction returning success does not mean kernel convergence succeeded.

Return/represent two statuses distinctly:

- desired state committed;
- current kernel convergence state.

Future HTTP can turn this into synchronous or asynchronous UX later.

## 13. Service health state

Expose a typed management runtime state sufficient for future Phase 7:

- database healthy;
- netd reachable;
- current desired generation;
- last converged generation;
- convergence pending/failed/converged;
- safe last failure category.

Do not expose secret/internal receipts wholesale.

## 14. Rootful restart harness

Create an integration test that runs actual management/netd process or realistic process-role instances against:

- a temp on-disk SQLite state;
- disposable namespaces;
- real kernel WireGuard;
- real RTNETLINK;
- real nftables.

The fixture must demonstrate process restart, not only reconstruction through one in-process object.

Use explicit child-process lifecycle with bounded timeouts.

## 15. Verification

Routine/MSRV.

Historical rootful tests remain green.

New rootful durable-restart suite should have one documented command and CI job or be incorporated into a clearly named existing rootful job without obscuring evidence.

## 16. Documentation

Add/update:

- `architecture/startup-recovery.md`;
- `architecture/state-store.md`;
- architecture overview;
- development instructions for durable restart fixture;
- registry/roadmap after closure.

Document that backup/restore/multi-version migration qualification remains M004.

## 17. Acceptance criteria

M003 closes only when:

1. management startup always loads/validates/project/reconciles current desired state;
2. committed-but-not-applied state recovers after restart;
3. partially applied state recovers after restart;
4. converged-but-unrecorded state safely replays idempotently;
5. stale generation completion cannot mark a newer generation converged;
6. deleted/drifted owned resources are restored;
7. lost/foreign ownership markers fail closed;
8. transient retry is bounded;
9. management never escalates privileges or bypasses netd;
10. real process + SQLite + kernel restart qualification passes.

## 18. Stop conditions

Stop/research if:

- management/runtime design requires HTTP framework decisions;
- reliable process-restart tests require installation/systemd implementation;
- a retry policy would create an unbounded repair loop;
- current convergence evidence cannot distinguish durable commit from kernel success;
- stale generations can still apply out of order.

## 19. Closure evidence

Record:

- startup sequence;
- coordinator queue/coalescing semantics;
- crash-point A–D results;
- kernel drift recovery results;
- ownership-loss conflicts;
- retry/backoff behavior;
- process-level rootful CI;
- state health projection;
- recommendation on M004 readiness.