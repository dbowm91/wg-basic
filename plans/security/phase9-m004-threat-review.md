# Phase 9 M004 — Adversarial Security Review

Review status: **in progress; evidence collected so far is not a closure record**

This report is the working M004 threat/security review. M004's final closure
record will cite its final revision and classify every finding.

## Actor and boundary review

| Actor | Expected reach | Security expectation |
|---|---|---|
| Unauthenticated remote/browser client | Configured HTTP listener | Host/Origin/CSRF boundary, fixed routes, bounded bodies/connections/timeouts, and generic failures prevent rebinding, cross-site mutation, and unbounded work. It cannot reach netd directly. |
| Authenticated administrator | Product API and embedded UI | Generation CAS, typed validation, single worker/store owner, audit, and per-client uniqueness prevent stale or malformed mutations from bypassing invariants. Authorized exports intentionally disclose client config. |
| Brute-force login/enrollment attacker | Login and one-time consume routes | Global/per-peer budgets run before Argon2 or capability lookup; unknown and refused credentials use indistinguishable outcomes; tokens are digest-only and one-use. |
| Unauthorized local UDS peer | Netd Unix socket | Peer credentials are checked before frame parsing; socket is mode 0660 under a private runtime directory. |
| Compromised authorized management UID | Typed UDS operations | Can issue only validated domain operations available to that UID. It cannot select executables, shell commands, arbitrary file paths, sysctl paths, nft source, or raw netlink messages. Availability can be denied by repeatedly using the authorized slow-connection window; each connection is bounded at two seconds and the listen backlog is 16. |
| Local root | All local state and processes | Root is outside confidentiality/availability protection. Ownership checks still prevent false claims that foreign state is managed or safe to delete. |
| Operator or competing network manager | Host WireGuard/nftables state | Installation owner tags, exact table marker, conflict classification, and typed mutation preserve unrelated links, routes, addresses, and firewall objects. |

## Existing adversarial evidence

| Surface | Evidence available in the repository |
|---|---|
| HTTP framing, admission and time | `service_resource_limits` exercises connection/in-flight/worker limits, oversize login body, login throttling, stalled header/body, slow handler and shutdown drain. `management_http` exercises real TCP routing, perimeter, response headers and generic bounded responses. |
| Authentication | `authenticated_api` qualifies limiter-before-hash, global/per-peer budgets, refusal equivalence, session revocation and CSRF policy. `auth_sessions` qualifies concurrent session caps and expired-row cleanup. |
| Enrollment | `product_management` qualifies one-use consume/replay, wrong token non-consumption, revocation, expiry, live-capability cap, pruning and retained audit. `client-enrollment.md` documents fragment-only token transport and GET non-consumption. |
| Product races and generation | Store/service tests qualify stale-generation refusal, uniqueness, atomic address reallocation and one audit event per committed mutation. Rootful product tests qualify changes against a real WireGuard peer and committed-but-degraded backend outage behavior. |
| UDS framing and authorization | Protocol framing tests qualify zero/oversize/truncated frames; socket tests qualify unauthorized peer rejection before parse, unknown protocol version, malformed payload isolation, continued legitimate Ping, and the measured authorized slow-peer window. `privileged_protocol` qualifies real Unix-socket credentials and safe socket-directory behavior. |
| Privileged operation review | `architecture_guards::process_execution_is_isolated_to_the_nft_backend`, `no_module_shells_out_through_a_shell`, and `the_nft_backend_spawns_exactly_nft_and_never_a_shell` constrain production process execution. The only `Command::new` is direct `nft` invocation in `src/firewall/nft.rs`; arguments and rendered input are internal and bounded. Typed request enums contain no generic escape hatch. |
| Ownership preservation | Rootful `durable_owner`, `network_reconcile`, `network_control_e2e`, `durable_backup`, and `product_management_rootful` exercise foreign same-name links, duplicate/foreign owner tags, foreign nft marker, unrelated host state and real traffic. |
| Secret exposure | `operational_events` scans representative secrets from human/JSON logs; `doctor_readonly` compares database and host state around JSON doctor; `product_management` asserts safe DTO/debug/audit fields; rootful service/product tests assert key material does not reach rendered responses. |
| Filesystem permissions | `state_store`, `state_backup_restore`, `service_lease`, `privileged_protocol`, and `maintenance_rootful` qualify database/backup modes, path/symlink refusal, private runtime directory, socket ownership/mode, service lease, restore, and purge safety. |
| Dependency/runtime | CI installs pinned `cargo-audit 0.22.2` with stable and scans the committed lockfile. Audit returned success with no advisories. Bundled SQLite reports 3.53.2; runtime test asserts newer than 3.51.2. No ordinary write authority moved from the management worker-owned store. |

## Provisional findings

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| M004-1 | Informational | An authorized local peer can hold the serialized netd accept loop for a measured 1.9618 seconds by withholding a frame; a 16-connection backlog bounds queued sockets. | Repeatability and deployment impact still require explicit M004 disposition. The management UID is within the trusted local control domain; no concurrent privileged mutation is added. |
| M004-2 | Low / evidence gap | There is no deterministic process kill injected at the exact interval after a product SQLite commit and before its HTTP response write. | Durable commit/restart and real backend-outage tests establish commit semantics, but this exact crash window must be addressed or explicitly accepted before M004/M005 closure. |
| M004-3 | Informational | Local root can read secret-bearing state and backups and can disrupt either service. | Outside confidentiality and availability protection; ownership checks still prevent accidental foreign-state takeover. |

No finding is being marked closed by this working report. The final M004 decision will require rerunning the complete ordinary/MSRV/rootful matrix and confirming no high/medium issue remains.
