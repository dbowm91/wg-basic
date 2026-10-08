# Operational Hardening M004 — Strict Closure

Disposition: **closed**

Implementation commits:

- `f821e3b` — `test: qualify operational abuse and generation races`
- `4c326f4` — `test: pin HTTP abuse boundaries`

Repository baseline: `11df6e8`  
Implementation head: `4c326f4`  
Closure-record head: recorded by the commit that adds this record.

## Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| Threat classes and risk boundary | `plans/security/phase9-m004-threat-review.md` records remote, authenticated, brute-force, unauthorized local, compromised authorized UID, root, and competing operator actors with their reachable surfaces and expectations. It classifies the accepted low/informational residuals. |
| HTTP framing/admission/deadlines | `service_resource_limits` qualifies connection and in-flight ceilings, oversized body refusal, login throttling, incomplete headers/bodies, handler timeout and shutdown. New real TCP boundary tests exercise 32/33 headers, 8,192/8,193 header bytes, 1,024/1,025 request-target bytes, 256/257 requests per keepalive connection, and total connection lifetime with a shortened valid test configuration. The server continues to answer health requests after rejected input. |
| Authentication/enrollment abuse | `authenticated_api`, `auth_sessions`, `product_management`, and rootful product suites cover global/per-peer login budgets before Argon2, indistinguishable refusal, concurrent session cap, one-use enrollment, wrong-token non-consumption, replay, revocation/expiry, per-client live cap, terminal pruning, and audit preservation. |
| Product generation races | `product_management::concurrent_same_generation_creates_have_exactly_one_winner` races two creates against one generation and address: exactly one commits, the other receives `StaleGeneration`, and generation advances once. Existing stale writer and unique-ID/address tests remain green. |
| Privileged UDS abuse | Framing and socket tests cover zero and oversized lengths before allocation, truncated headers/payloads, malformed JSON, unknown protocol versions, unauthorized peer rejection before payload parse, slow peer timeout, and continued service. New `malformed_peer_burst_does_not_prevent_a_later_authorized_request` submits 128 malformed connections and then proves an authorized Ping succeeds. Real credential/socket behavior is covered by `privileged_protocol`. |
| Authorized-UID availability risk | Measured stall is 1.961817907 seconds for one authorized peer withholding the frame, with `IO_TIMEOUT=2s`; backlog is 16 and requests remain single-threaded. Classified informational for the dedicated trusted UID; recorded in the threat report for M005. |
| Privileged operation and nft subprocess review | Existing static guards assert all production process execution is in `src/firewall/nft.rs`, direct `nft` only, no shell, no generic executable/path/file/sysctl/nft-source/raw-netlink operation. Typed protocol request validation rejects malformed operations before mutation. |
| Host ownership and preservation | Rootful `durable_owner`, `network_reconcile`, `network_control_e2e`, `durable_backup`, and `product_management_rootful` passed against real namespaces, WireGuard, RTNETLINK and nftables, preserving foreign same-name links, duplicate/foreign owner tags, foreign table marker, unrelated state and actual traffic. Their full result set is recorded in the M003 closure matrix and was rerun against the M003 implementation before M004 closure. |
| Secret exposure and permissions | `operational_events` scans a recognizable corpus across human/JSON event logs; doctor, API, product DTO/audit, and rootful HTTP tests cover output secrecy. `architecture_guards` verifies no argv/environment password input path. Store, backup/restore, lease, UDS and purge suites cover 0600 state/backup files, parent/socket permissions, symlink rejection, restore safety and purge ownership. No reachable secret leak was found. |
| Dependency/advisory and SQLite runtime | CI now has a pinned `cargo-audit 0.22.2` job using stable independently of the 1.89 application MSRV. `cargo audit` succeeds with no advisory findings over 149 locked packages. `cargo tree --locked` was reviewed. `architecture_guards` verifies bundled SQLite 3.53.2, later than 3.51.2; state-store tests continue to pin WAL and `synchronous=FULL`. No runtime dependency changed. |
| Security disposition | The threat report records no open high/medium finding. A low evidence gap remains for an instruction-level kill exactly between product commit and HTTP response; M005 must resolve it with deterministic evidence or an explicit transaction-level rationale. Local root remains outside confidentiality/availability protection. |

## Verification run

All listed commands passed against implementation head `4c326f4`:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked                                      # 526 passed, 1 ignored, 30 suites
rtk cargo audit                                                # success; no advisories
rtk cargo tree --locked                                       # 149 locked packages reviewed
rtk cargo test --locked --test product_management             # 28 passed
rtk cargo test --locked --test privileged_protocol -- --nocapture # 2 passed
rtk cargo test --locked --test service_resource_limits         # 20 passed in full suite
rtk cargo test --locked --test service_resource_limits header_count_boundary_accepts_32_and_rejects_33_without_losing_service
rtk cargo test --locked --test service_resource_limits header_byte_limit_accepts_8192_and_rejects_8193_bytes
rtk cargo test --locked --test service_resource_limits request_target_limit_accepts_1024_bytes_and_rejects_1025
rtk cargo test --locked --test service_resource_limits a_keepalive_connection_is_closed_after_256_requests
rtk cargo test --locked --test service_resource_limits total_connection_lifetime_closes_a_still_open_keepalive_socket
rtk cargo test --locked malformed_peer_burst_does_not_prevent_a_later_authorized_request
rtk proxy sudo -n -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1 # 6 passed
```

The entire rootful regression matrix passed on the same M003 implementation head: `maintenance_rootful` 1, `durable_owner` 10, `durable_restart` 9, `durable_backup` 2, `doctor_readonly` 2, `wireguard_kernel` 2, `network_reconcile` 2, `network_control_e2e` 2, and `service_rootful_e2e` 3. `product_management_rootful` passed all six tests after updating its readiness parser for structured `netd.started` events.

## Known limitations and unresolved findings

No high or medium finding remains open. Accepted low residual M004-2 is the exact post-commit/pre-response process-kill evidence gap; M005 owns explicit resolution. The authorized same-UID slow-peer denial is bounded per connection but repeatable, and is informational within the dedicated trusted control UID. Local root can read secret-bearing files and disrupt the services by design.

## Handoff

M004 is strictly closed. M005's hard dependency is satisfied and M005 is active. Phase 10 remains blocked until M005 strictly closes Phase 9.
