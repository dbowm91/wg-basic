# Distribution M002 Closure — System Install and Service Layout

Status: closed

Source plan: `plans/implementation/distribution/002-system-install-and-service-layout.md`

Roadmap: `plans/subsystems/distribution-install-update-roadmap.md`

Implementation commits: `432299c` through `d1813da` on top of M001 closure head `80005e5`.

Final implementation head: `d1813da`.

## Requirement-to-evidence matrix

| Requirement | Evidence | Result |
|---|---|---|
| Canonical system, state, and runtime layout with safe owner/mode checks | `src/distribution.rs` defines the canonical paths, checks path components and existing objects, and creates root-owned install metadata/lock. State remains management-owned. | Pass |
| Deterministic system identities and NSS-backed netd authorization | Product sysusers definitions create `wg-basic`, `wg-basic-netd`, and group `wg-basic`; `netd --allow-user` resolves account names and deduplicates numeric UIDs. | Pass |
| Hardened systemd services registered through Eggup-service | Exact product unit bytes preserve Phase 9 restrictions; installation uses Eggup-service 0.1.2 and refuses modified owned units. Doctor runs as the management user before service startup; advisory warnings do not prevent service recovery. | Pass |
| Safe state initialization and preservation | `state init` creates under the effective management UID and validates existing databases without recreating them. The systemd qualification seeds state first and verifies installation retains its identity and mode. | Pass |
| Root-owned durable install receipt and transaction lock | Receipt is written after service and health checks; installation lock is exclusive and released on process exit. Status validates metadata and exact owned file bytes. | Pass |
| Foreign/modified destinations fail closed; exact owned reinstall works | Systemd qualification rejects a foreign candidate binary, accepts exact owned reinstall, rejects a modified unit, and verifies service identities/capabilities/socket permissions. | Pass |
| Fresh installed services pass doctor and health smoke | CI systemd qualification confirms the empty-install doctor report is `pass`, waits for service readiness, checks `/healthz`, and repeats the owned install. | Pass |
| Rust and existing CI remain green | Local `cargo fmt --all`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (542 passed, 3 ignored), and `cargo +1.89.0 check --all-targets --locked`; full hosted CI run [37799075225](https://github.com/dbowm91/wg-basic/actions/runs/37799075225) passed, including `system-install-systemd` job `113386144633`. | Pass |
| Release foundation remains qualified | Distribution foundation run [37799075240](https://github.com/dbowm91/wg-basic/actions/runs/37799075240) passed. | Pass |

## Security, ownership, and compatibility evidence

- The service account owns `/var/lib/wg-basic` and its database; netd receives only `CAP_NET_ADMIN` and cannot read the state database.
- The management service has no effective, ambient, or bounding capabilities. The socket is owned by netd and the service group, and the qualification rejects an unrelated UID.
- Existing state data is never removed by installation. For pre-existing state, the receipt reports the doctor disposition as `unknown` because M002 does not infer an aggregate result from systemd logs. A fresh state install records the verified `pass` result.
- `--allow-warnings` is limited to the service pre-start doctor invocation so recoverable advisory drift does not prevent the management service from starting. Required failures still fail startup.
- No update, release discovery, uninstall, host-network mutation, or implicit privilege escalation was added.

## Documentation and operations evidence

Operator and developer documentation describes local installation scope, required systemd/system-user behavior, safe path requirements, doctor behavior, and the fact that update/uninstall remain unavailable until later milestones. No installation or self-update feature is presented as production release signing.

## Limitations and findings

- The production Minisign trust root remains unprovisioned. M003 may qualify fixture signing and draft handoff, but public production signing remains gated on maintainer provisioning.
- The installer supports only the planned Linux GNU x86_64/aarch64 systemd profile; no other service manager or package format is claimed.
- No high, medium, or low M002 implementation finding remains open.

Disposition: **closed**. Distribution M003 is unblocked and ready.
