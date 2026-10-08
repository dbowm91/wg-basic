# Product Management M004 Closure — Live Telemetry and Audit Surface

Status: closed.

Implementation commit: `d629103` — `feat: add live client telemetry and audit paging`.
Planning baseline: M003 closure at `bc19c83`.
Final implementation head: `d629103`.
Disposition: **closed**.

## Requirement-to-evidence matrix

| Requirement | Evidence |
| --- | --- |
| Reuse typed privileged observation | `ManagementRuntime::observe_wireguard_device` issues the existing `ObserveWireGuardDevice` operation. HTTP calls `WorkerClient::client_telemetry`; it cannot access netd directly. No protocol vocabulary or migration was added. |
| Stable client mapping and drift | Worker projection joins observed peer public keys to durable product clients, then emits ClientId/PeerId, enabled state, present/missing status, and drift. The bounded 4,096-client unit fixture checks missing clients, extras, drift, truncation, and the 1,024 row ceiling. |
| Time and counter semantics | `last_handshake` is normalized from the protocol's elapsed `Duration` into absolute Unix seconds plus derived age; endpoint and RX/TX values are copied from the fresh observation. Product API architecture docs state these units and semantics. |
| Fresh, bounded, non-durable telemetry | Authenticated `GET /api/v1/clients/telemetry` performs one fresh worker observation and returns no-store JSON, at most 1,024 clients, explicit truncation and unassociated-peer count; unavailable netd returns bounded 503. HTTP tests compare audit state around repeated telemetry reads, and the worker path contains no store mutation. |
| Bounded newest-first audit pages | Authenticated `GET /api/v1/audit` returns at most 100 events; the canonical timestamp/event UUID path continues the stable cursor. Store query uses a fixed newest-first query and bounded limit. Real HTTP coverage verifies page size, ordering, cursor continuation, and final-page behavior. |
| Secret-safe audit projection and perimeter | Audit JSON exposes event/principal/action/resource/generation/outcome only. HTTP assertions reject private-key, PSK, and token-digest markers. All routes require session authentication, and centralized response sealing supplies no-store/security headers. |
| Real authenticated kernel telemetry | Rootful `exported_client_config_establishes_a_real_kernel_handshake` creates/configures a second namespace from the exported config, establishes a real WireGuard handshake and traffic, and reads handshake/RX/TX through authenticated HTTP. It verifies stable IDs, endpoint, enabled/present/no-drift state, disabled/missing behavior, manually observed disabled-peer drift, an unassociated peer, and restored observation after re-enable. Audit history contains the safe mutation event and is unchanged by observation. |
| No alternate authority | Telemetry is never stored. Audit reads are read-only. Product state changes remain worker commands; no raw process execution, host-network mutation, direct HTTP-to-netd access, or new privileged operation was introduced. |

## Verification performed

All commands passed against implementation head `d629103`:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked                         # 493 passed, 24 suites
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
                                                  # 6 passed, real namespaces/kernel
```

The rootful test uses a real client namespace and actual WireGuard devices;
telemetry is fetched through the authenticated loopback HTTP service after the
kernel handshake and data transfer. HTTP pagination and unavailable-backend
behavior are also exercised through the real service fixture.

## Security, ownership, and findings

Observation remains read-only and worker-owned. Public output is bounded and
contains no private or preshared key material. Audit uses stable typed cursor
fields and fixed SQL, without raw query fragments or request/config payloads.
The implementation adds no durable telemetry fields, schema migration,
WebSocket, polling service, arbitrary execution, or host-network mutation.
No high, medium, or low finding remains open.

M005 is unblocked and active. M001–M003 closure records remain unchanged.
