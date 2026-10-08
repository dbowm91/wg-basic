# Operational Hardening M003 — Strict Closure

Disposition: **closed**

Implementation commit: `5815c59` (`feat: harden operational logging and runtime bounds`)

Repository baseline: `9f2d936`  
Implementation head: `5815c59`  
Closure-record head: recorded by the commit that adds this record.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Structured secret-safe events and output formats | `src/operational.rs` defines the closed event schema and human/JSON stderr renderers. The CLI has global `--log-format human|json`; command results remain stdout. `tests/operational_events.rs` parses each JSON line, checks human format and stdout/stderr separation, and scans representative password, verifier, token, key, config, and body secrets. `tests/architecture_guards.rs` pins the schema and service-manager contract. The binary owns no log files or rotation. |
| Session housekeeping | Startup removes expired sessions; insertion prunes expired rows and caps each principal at 32 live sessions, evicting the oldest deterministically. Concurrent issuance and generation invariance are covered in `tests/auth_sessions.rs`; startup pruning is covered in `tests/service_lease.rs` and `tests/service_resource_limits.rs`. |
| Enrollment housekeeping and audit retention | Each client is capped at eight live capabilities. Startup and creation prune terminal capability rows older than seven days while preserving audit history. Product audit insertion retains the newest 10,000 rows, ordered by timestamp and event ID, within the caller's transaction and without changing desired generation. Covered by `tests/product_management.rs` and store unit tests. |
| Serve/netd process restart | `service_lease` executes 20 real serve SIGKILL/restart cycles, verifies lease release and stable parent descriptors/tasks, and checks startup session cleanup. `service_e2e::netd_sigkill_reclaims_only_its_stale_socket_across_bounded_restart_cycles` executes 20 netd SIGKILL/restart cycles, proves only the stale owned socket is replaced, and checks bounded descriptor/thread counts. `durable_restart` and product rootful evidence cover durable convergence and the disabled network remaining disabled across backend/management restart. |
| Bounded runtime resource growth | `tests/runtime_stability.rs` issues 200 valid and 200 rejected Host requests against a real serve child. It asserts file descriptors grow by at most two, task count does not grow, RSS growth remains below 16 MiB, and session/enrollment/audit row counts are unchanged. Existing exact HTTP admission/deadline qualification remains in `service_resource_limits`; protocol framing and malformed-peer isolation remain covered by `privileged_protocol` and protocol tests. |
| Netd slow-authorized-peer denial window | The authorized same-UID slow-peer fixture measured **1.961817907 seconds** against `IO_TIMEOUT=2s`. The server is intentionally serialized, so an authorized same-UID process can repeat this bounded stall; M004 owns deployment-severity assessment. |
| Phase 10 service-manager handoff | `architecture/service-hardening.md` specifies serve/netd users, capabilities, filesystem/address-family restrictions, paths, task/memory ceilings, core policy, restart limits, and the direct `/proc/sys/net/ipv4/ip_forward` write. It expressly forbids claiming `ProtectKernelTunables=yes` for netd under current ownership. No service unit is claimed as shipped. |
| Dependency/runtime qualification | No runtime dependency was added. `cargo tree --locked` reviewed the 149 locked packages. Pinned `cargo-audit 0.22.2` reported no advisories. Runtime guard and bundled header identify SQLite **3.53.2**, beyond the 3.51.2 WAL-reset affected range. `WAL` and `synchronous=FULL` remain enforced by the existing state-store connection contract. |
| Network ownership / regression evidence | Rootful suites passed against real disposable namespaces, WireGuard, RTNETLINK, nftables, and traffic. No network mutation or ownership boundary changed in M003. |

## Verification run

All listed commands passed against implementation head `5815c59` (the implementation commit itself was followed by plan/closure bookkeeping):

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked                                      # 518 passed, 29 suites
rtk cargo test --locked --test service_resource_limits        # 15 passed
rtk cargo test --locked --test service_e2e -- --test-threads=1 # 5 passed
rtk cargo test --locked --test architecture_guards            # 47 passed
rtk cargo test --release --locked --test service_footprint -- --nocapture # 2 passed
rtk cargo audit                                                # no advisories
rtk cargo tree --locked                                       # 149 packages reviewed
rtk proxy cargo test --locked authorized_slow_peer_blocks_one_at_a_time_service_for_at_most_io_timeout -- --nocapture
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test maintenance_rootful -- --test-threads=1 # 1 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1 # 6 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1 # 10 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1 # 9 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1 # 2 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test doctor_readonly -- --test-threads=1 # 2 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test wireguard_kernel -- --test-threads=1 # 2 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_reconcile -- --test-threads=1 # 2 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test network_control_e2e -- --test-threads=1 # 2 passed
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test service_rootful_e2e -- --test-threads=1 # 3 passed
```

Release footprint measured serve RSS 9.21 MiB, netd RSS 5.03 MiB, combined 14.24 MiB, zero idle CPU ticks for each role over two seconds, and 38.55 ms median login including Argon2id. The 256 MiB serve and 128 MiB netd recommendations retain substantial headroom.

## Known limitations and unresolved findings

No high, medium, or low M003 finding remains open. The same-UID slow-peer stall is bounded per connection but repeatable; M004 must classify its availability impact for the target deployment. The post-commit/pre-HTTP-reply crash point has durable commit/restart and committed-but-degraded evidence, but no injected instruction-level process kill between the SQLite commit and response write; this evidence limit is carried explicitly for M004/M005 review. Systemd limits are recommendations until Phase 10 installs units and measures cgroup accounting.

## Handoff

M003 is strictly closed. M004's hard dependency is satisfied and M004 is active. M005 remains blocked on M004. Phase 10 remains blocked on M005/Phase 9 closure.
