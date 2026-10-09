# Product management API

This document describes behavior implemented by Phase 8 M001–M005. Phase 8 is
closed as the first user-facing product boundary.

## Authority and mutation path

The SQLite desired state and product metadata are authoritative. HTTP handlers
translate bounded JSON into typed worker commands; they do not open SQLite,
allocate addresses, generate keys, or call `netd`. The single management worker
commits a compare-and-swap mutation and then reconciles it. The receipt keeps
the durable commit generation separate from kernel enforcement.

Client creation always allocates an IPv4 address and, when an IPv6 tunnel prefix
is configured, also allocates an IPv6 address. An exact address can be requested
per family. Disabled clients retain both address reservations, their row, peer
identity, and key; only the peer's projected kernel intent is removed. Deletion
removes the durable client and peer and returns the worker's enforcement result.
IPv6 tunnel addressing is independent from forwarding. Server setup keeps IPv6
forwarding disabled by default; an explicit setting persists IPv6 forwarding
policy for the managed tunnel prefix. Forwarding uses the host-global Linux
control, remains enabled when policy is disabled, requires upstream routing,
and does not use NAT66.

Client route policy is explicit and independent for IPv4 and IPv6. Operators
may select no route, the family's full-tunnel default (`0.0.0.0/0` or `::/0`),
or split prefixes; every policy is limited to 64 unique unicast prefixes.
IPv6 routes are accepted only when the server has a managed IPv6 tunnel pool
and the client has an assigned IPv6 tunnel address. Assigning that address
does not enable any route. Client routes are rendered as the client's
`AllowedIPs`; server peer `AllowedIPs` continue to contain only assigned client
tunnel addresses. Route selection does not itself prove upstream IPv6
reachability; M004 namespace qualification proves the supported full/split
route behavior with explicit upstream and return routes. Operators must arrange
those upstream routes in their own network.

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
| GET | `/api/v1/clients/<uuid>/config` | Download the standard WireGuard config |
| GET | `/api/v1/clients/<uuid>/qr` | Render the config as local SVG QR |
| POST | `/api/v1/clients/<uuid>/enrollment-links` | Create a short-lived share link |
| DELETE | `/api/v1/enrollment-links/<uuid>` | Revoke an unused share link |
| GET | `/enroll/<uuid>` | Load the static enrollment page without consuming the link |
| POST | `/api/v1/enroll/<uuid>/consume` | Consume a valid capability exactly once |
| GET | `/api/v1/clients/telemetry` | Observe live WireGuard peer telemetry |
| GET | `/api/v1/audit` | Read the newest audit page |
| GET | `/api/v1/audit/<unix-seconds>/<event-uuid>` | Read the next stable audit page |

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
the projection types. Config and QR are explicit secret-bearing exports and
always use `Cache-Control: no-store`; config is an attachment. Enrollment
tokens contain 256 random bits, are stored only as SHA-256 digests, expire after
10 minutes by default (operator-selectable up to 24 hours), and are returned
only in the URL fragment. The landing page moves the token into a same-origin
bounded POST; GET never consumes it. A separate limiter runs before capability
lookup, and the state transaction consumes and audits the token atomically.
Audit rows contain no config or token data.

Telemetry is a fresh read-only observation through the worker and existing
`ObserveWireGuardDevice` operation. Peers are joined to product records by
public key, then returned with stable client/peer IDs, present/missing state,
drift, endpoint, absolute Unix-second handshake time and age, and byte counts.
It is never written to SQLite. At most 1,024 client rows are returned; an
explicit `truncated` flag identifies larger installations. Audit pages contain
at most 100 immutable events and use timestamp plus event ID to continue
newest-first ordering.

Each client may have at most eight live enrollment capabilities. Startup and
capability creation prune consumed, revoked, or expired capability rows older
than seven days; their audit events remain. Audit storage retains the newest
10,000 rows, deleting oldest rows deterministically by timestamp and event ID
inside the writing transaction. Retention does not advance DesiredGeneration.

## Operator UI

The embedded operator page is a buildless same-origin client of these routes.
It provides login, first-server setup, separate IPv4 and IPv6 route controls for
no route, full tunnel, and split prefixes, server and client status, client
create/edit/enable/disable/delete, explicit config/QR export, one-time link
create/revoke, bounded visible-page telemetry refresh, and recent audit
history. Mutations carry the generation from the latest API read; a `409`
refreshes current state and asks the operator to review before trying again.
Committed but not enforced mutations retain an explicit pending/degraded
message, with disable/delete wording that does not claim access was revoked.
Credential artifacts are loaded only after an operator action and are cleared
from the dialog on close; the UI does not persist them in browser storage.

## Operational boundary

Administrator bootstrap and reset remain local CLI operations. The HTTP setup
route configures the WireGuard server only after login; it does not create the
administrator. The product API does not add arbitrary hooks, firewall rules,
TLS termination, installation, or update behavior. Multi-interface product
workflows remain deferred. Dual-family client route selection is explicit and
does not claim end-to-end routed traffic.
