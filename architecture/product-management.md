# Product management API

This document describes behavior implemented by Phase 8 M001 and M002.
Export, QR, one-time enrollment, telemetry, audit queries, and the operator UI
are separate later milestones and are not implied here.

## Authority and mutation path

The SQLite desired state and product metadata are authoritative. HTTP handlers
translate bounded JSON into typed worker commands; they do not open SQLite,
allocate addresses, generate keys, or call `netd`. The single management worker
commits a compare-and-swap mutation and then reconciles it. The receipt keeps
the durable commit generation separate from kernel enforcement.

Client creation allocates the lowest free IPv4 address within the configured
tunnel prefix unless the caller requests a specific available address. Disabled
clients retain their row, peer identity, key, and address reservation; only the
peer's projected kernel intent is removed. Deletion removes the durable client
and peer and returns the worker's enforcement result.

## HTTP contract

All product routes require a live administrator session and pass the same
`Host` and response-header policy as the rest of the service. Unsafe methods
also require the exact canonical `Origin` and session CSRF token. There is no
CORS policy. Setup, create, update, enable, disable, and delete use an explicit
8 KiB JSON body ceiling and carry `expected_generation`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/server` | Safe server summary and current generation |
| POST | `/api/v1/setup` | Configure the single managed server |
| GET | `/api/v1/clients` | Safe client summaries and current generation |
| POST | `/api/v1/clients` | Create one client |
| GET | `/api/v1/clients/<uuid>` | Read one client summary |
| PATCH | `/api/v1/clients/<uuid>` | Change typed client fields |
| POST | `/api/v1/clients/<uuid>/enable` | Enable the client |
| POST | `/api/v1/clients/<uuid>/disable` | Disable the client |
| DELETE | `/api/v1/clients/<uuid>` | Delete the client |

IDs must be canonical lowercase UUIDs and routes match exact path segments.
Unknown or malformed IDs return a bounded not-found answer. Setup is one-time;
repeating it returns conflict rather than replacing the configured interface.

Mutations return `200`/`201` when the commit is enforced and `202` when the
commit is durable but network enforcement is pending or degraded. Stale
generations return `409` before any mutation. Validation errors return `422`;
state unavailability returns `503`. A disable/delete response marks
`revocation_confirmed` false if the backend has not confirmed the committed
change.

Ordinary response shapes contain identifiers, public keys, labels, addresses,
routes, DNS policy, keepalive policy, timestamps, and bounded enforcement
metadata. Private keys, preshared keys, and enrollment tokens are absent from
the projection types.

## Operational boundary

Administrator bootstrap and reset remain local CLI operations. The HTTP setup
route configures the WireGuard server only after login; it does not create the
administrator. The product API does not add arbitrary hooks, firewall rules,
TLS termination, installation, or update behavior. IPv6 production
qualification and multi-interface product workflows remain deferred.
