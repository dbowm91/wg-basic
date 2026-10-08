# Product Management M002 Closure — Authenticated Product CRUD API

Status: closed.

Implementation commit: `cf0717e` — `feat: expose generation-safe product CRUD API`.
Planning repository baseline: `9e99508`.
Final implementation head: `cf0717e`.
Disposition: **closed**.

## Requirement-to-evidence matrix

| Requirement | Evidence |
| --- | --- |
| Setup/server summary and client list/detail | Exact closed routing table in `src/http/service.rs`; real HTTP assertions in `authenticated_product_crud_uses_generation_cas_and_reports_degraded_commit`. |
| Create/update/enable/disable/delete | Typed `WorkerClient` commands only; loopback wire test covers every operation; rootful HTTP fixture proves the lifecycle reaches a real WireGuard device. |
| Dynamic route exactness | Canonical lowercase UUID parsing, exact segment-count matching, and near-miss tests in `http::service::tests::dynamic_product_routes_require_canonical_uuid_and_exact_segments`. |
| Host/Origin/session/CSRF perimeter | Product routes remain inside `ManagementService::route_request`; the real wire test rejects missing CSRF on setup/create/update/enable/disable/delete. Existing `management_http` and `authenticated_api` suites pass. |
| Explicit body bounds and JSON handling | Login remains 4 KiB; each product JSON mutation is capped at 8 KiB and must declare JSON. The full management HTTP suite passes. |
| Generation compare-and-swap | Every unsafe request carries `expected_generation`; the real HTTP test submits a stale generation, receives `409`, and then completes a mutation at the unchanged current generation. |
| Truthful commit/enforcement status | The absent-netd HTTP test verifies durable setup/client/toggle/delete operations return `202`; delete reports `revocation_confirmed:false`. The rootful suite verifies converged HTTP mutations return `200`/`201`. |
| Secret-safe projections | `ProductClient`, `ProductServer`, and settings serialize only fields in their summary types; the real wire test scans create output for private-key fields and confirms list/detail work. |
| Setup is authenticated and one-time | Setup is behind session and CSRF checks; worker rejects a second configured server as conflict. |
| Product UI/config/enrollment remain out of scope | Route inventory has no config, QR, telemetry, audit-query, or enrollment route; current behavior docs identify those as later Phase 8 work. |

## Verification performed

All commands ran against implementation commit `cf0717e` and passed:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo test --locked                         # 486 passed, 24 suites
rtk cargo +1.89.0 check --all-targets --locked
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
                                                  # 5 passed, real namespaces/kernel
```

The rootful test `authenticated_http_crud_applies_real_peer_lifecycle` drives
setup, create, disable, enable, and delete through real EggServe HTTP while
`netd` runs inside a disposable namespace. It observes the actual WireGuard
device after each operation. The unprivileged real-TCP suite separately proves
the committed-but-degraded `202` path against an unavailable backend.

## Security and ownership evidence

The HTTP module reaches product state only through `AuthenticatedApi::worker()`
and the existing bounded `WorkerClient`; no database or privileged protocol
access was added to request handlers. Server and client summaries have no
private-key or preshared-key field. Request bodies are bounded before buffering,
IDs are parsed as canonical UUIDs, errors render bounded categories, and all
response construction retains no-store and the single central security-header
seal. No arbitrary command, filesystem, netlink, hook, or firewall input was
added.

## Findings and disposition

During qualification, two implementation defects were corrected before closure:

1. The initial empty-body guard also rejected POST `/api/v1/clients`, which
   surfaced as an authentication-shaped refusal. The wire-level test exposed
   it; empty-body validation is now limited to read methods.
2. Initial mutation status wiring mapped degraded enforcement to `200`. The
   receipt test caught it; all committed-but-degraded operations now return
   `202` as specified.

No high, medium, or low finding remains open. No dependency was added. M003 is
ready under its hard dependency on this strict M002 closure.
