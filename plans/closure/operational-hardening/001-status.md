# Operational Hardening M001 — Strict Closure

Disposition: **closed**

Implementation commit: `3e5b21c` (`feat: implement authoritative read-only doctor`)

Repository baseline: `e8fd6b1212491576f3c6bdd7468591a97d5aaf3c`  
Implementation head: `3e5b21c`  
Closure-record head: recorded by the commit that adds this record.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Typed bounded report, stable check IDs, human/JSON output, exit contract | `src/doctor.rs`; `src/main.rs`; unit tests in `src/doctor.rs`; `tests/doctor_readonly.rs`. Exit status is 0 for all pass, 1 for warning/unknown, and 2 for required failure or invalid invocation. JSON is one report on stdout. |
| Read-only state safety, schema, integrity, typed product/convergence and recovery-artifact checks | `src/state/diagnostic.rs`; immutable SQLite URI, owner/mode and no-symlink validation, WAL/SHM refusal, quick check, foreign-key check, schema floor/ceiling, typed snapshots. `doctor_json_does_not_change_database_or_host_network_state` verifies unchanged database bytes/files. |
| SQLite runtime/source identity and WAL safety floor | Doctor reports SQLite `3.53.2`, source ID `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`; the typed version guard requires at least `3.51.3`. No system SQLite dependency was introduced. |
| netd, runtime identity/capabilities, kernel identity, and optional HTTP policy | Reuses typed `InspectCapabilities`; HTTP uses the production `ServeConfig` constructors without binding. Unit tests cover SQLite version parsing and report rendering. |
| RTNETLINK, nftables and WireGuard observations | Aggregate plan-only request exercises RTNETLINK and nftables observations; a typed WireGuard device observation checks the configured interface. Backend details are reduced to bounded classifications. |
| Forwarding and managed drift/conflict | Doctor reads only `/proc/sys/net/ipv4/ip_forward`. Rootful fixture covers configured-but-unapplied drift (Warn), applied/converged state (Pass), and foreign same-name interface conflict (Fail). |
| Interface/listen-port honesty | Existing managed device with matching port passes; mismatch warns; missing/ambiguous active device remains Unknown. Doctor never binds a UDP port. |
| No mutation, no secrets, no arbitrary process execution, no Apply | Rootful fixture snapshots namespace links, routes, nftables, and database across doctor calls for drift, convergence, and conflict. Ordinary fixture snapshots database and host network state. `architecture_guards::doctor_uses_only_immutable_state_reads_and_plan_operations` pins the typed plan/immutable-read boundary and rejects Apply, shell execution, and StateStore open. Report tests check secret exclusion. |
| Service lease seam | Stable `ServiceLease` check reports Unknown with explicit M002 handoff; it does not claim singleton enforcement. |

## Verification run

All commands below passed on the implementation tree:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo test --locked                         # 502 passed, 25 suites
rtk cargo +1.89.0 check --all-targets --locked
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test doctor_readonly -- --test-threads=1 --nocapture
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test wireguard_kernel -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_reconcile -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_control_e2e -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
rtk sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test service_rootful_e2e -- --test-threads=1
```

Each rootful target passed. The expanded doctor target passed after its final fixture change; the ordinary suite, formatting/check/Clippy, and MSRV gates passed immediately before that test-only expansion. The rootful suite set includes real WireGuard handshakes, RTNETLINK, nftables, forwarding/NAT, process restart, product lifecycle, and unrelated-state preservation.

## Docs and security/ownership evidence

`docs/development.md` documents doctor flags, exit semantics, immutable state behavior, and the dedicated rootful fixture. CI now runs `doctor_readonly` as a rootful Linux job. The only dependency/runtime change relevant to M001 is reporting the already-locked bundled SQLite runtime; no dependency was added.

## Known limitations and unresolved findings

No high, medium, or low severity finding remains open. Two intentional unknowns remain informational and fail safe:

- When the managed interface is absent, or an unrelated UDP consumer cannot be identified without binding, listen-port availability is Unknown. This is the plan's required non-mutating uncertainty behavior.
- An absent managed WireGuard device cannot prove Generic Netlink device observation; the check remains Unknown while ownership planning reports the more authoritative backend outcome. M001 does not create a probe interface.

Service singleton state is Unknown until M002. No diagnostics repair state, bind a port, apply an intent, or delete a resource.

## Handoff

M001 is strictly closed. M002's only hard dependency is this closure, so M002 is unblocked and active. M003–M005 remain blocked behind their direct predecessors. Phase 10 remains blocked on M005/Phase 9 closure.
