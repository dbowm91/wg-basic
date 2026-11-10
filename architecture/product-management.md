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
| GET | `/api/v1/network-prerequisites` | Read forwarding, attachment lines, and the current policy verdict |
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
metadata. A client summary also carries `expires_at`, a derived
`expiry_state` of `none`, `scheduled`, or `expired`, `preshared_key_configured`,
and `mtu`. Private keys, preshared key bytes, and enrollment tokens are absent
from the projection types. Config and QR are explicit secret-bearing exports and
always use `Cache-Control: no-store`; config is an attachment. A configured
preshared key and a client MTU appear only in that export. Enrollment
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

`GET /api/v1/network-prerequisites` is an authenticated read with no body and
no CSRF token. `host_platform` is the platform this binary was built for.
Forwarding is `enabled`, `disabled`, or `not_observed`. A missing network
service is `not_observed` with no verdict. A conflict or an unsupported plan
is a named `refusal`. On macOS the reply includes the three administrator
attachment lines, their section order, and the anchor file. Linux replies
omit that object. The route plans through the existing network-policy plan
operation and does not apply it.

An omitted setup `mode` still derives the policy: forwarding or masquerade
stores a gateway, and neither stores host-only. An explicit `gateway` mode is
accepted with those settings. The embedded page starts from
`GET /api/v1/network-prerequisites` when the form has not been edited. Linux
leaves IPv4 forwarding and masquerade checked and egress at `eth0`. macOS
clears both and the egress value, and uses `en0` as a placeholder. Any other
platform clears both and shows that the platform is unknown. Choosing gateway
or routed LAN on macOS shows the lines or filter rules and states that the
product will not write them.

A client `expires_at` is Unix seconds on the management worker's clock, or
null for never. A value at or before that clock is rejected and nothing is
written. The worker disables a due client through the existing disable path,
keeps the row, addresses, and keys, and audits `client_expire`. It sleeps at
most until the next stored deadline and does not sleep when none is stored.
The clock is the authority. A step during that sleep is noticed when the
sleep ends. NTP is not detected. Enabling a client whose stored deadline is
still past is rejected unless the same request sets a future deadline or
clears it.

Create accepts `preshared_key` only as `"generate"`. Update accepts `"generate"`
or `"clear"`; omitting the field leaves the stored key. Any other JSON,
including raw key bytes, is rejected before the worker stores it. Generate
draws a new key from the same CSPRNG as identity keys and replaces the stored
one. Clear removes it. The summary boolean is the only non-export view. Audit
actions are `client_preshared_key_set` and `client_preshared_key_clear`, and
they carry the client id and no secret. A device must re-import the config
after a generate or a clear. The key is not rolled back when a later kernel
patch fails.

`mtu` is an optional integer from 1280 through 9000. Omit on create stores
null. Omit on update leaves the stored value. Null clears it. The export
writes `MTU = <n>` in `[Interface]` after `Address` and before `DNS`, and the
QR code is that same text. The server link MTU is unchanged.

## Operator UI

The embedded operator page is a buildless same-origin client of these routes.
It provides login, first-server setup, separate IPv4 and IPv6 route controls for
no route, full tunnel, and split prefixes, server and client status, client
create/edit/enable/disable/delete, an optional deadline, a generate-or-clear
preshared key, an optional client MTU, name/address/state/expiry filters over
the loaded client list, explicit config/QR export, one-time link
create/revoke, bounded visible-page telemetry refresh, and recent audit
history. Saving a client does not send a preshared-key verb. Generate and
clear are separate requests, and the page says a device must re-import.
Enabling a client whose expiry state is `expired` clears the deadline in that
request. Mutations carry the generation from the latest API read; a `409`
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
