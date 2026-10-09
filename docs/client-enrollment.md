# Client configuration and enrollment

An authenticated administrator can download a managed client's standard
WireGuard configuration or request a local SVG QR encoding of that exact
configuration. Both artifact responses are marked `Cache-Control: no-store`;
the config response is an attachment. A client without an allowed route policy
cannot be exported because it would produce an unusable `AllowedIPs` setting.
Client route intent is selected explicitly per family: no routes, that family's
full tunnel (`0.0.0.0/0` or `::/0`), or split prefixes. IPv6 routes require both
a managed server IPv6 tunnel range and an IPv6 address assigned to that client;
assigning an IPv6 address alone never enables IPv6 routes. Route policies are
limited to 64 unique unicast prefixes. Export preserves the selected routes,
DNS addresses, and a bracketed IPv6 endpoint literal where configured.
Hosted namespace qualification covers IPv4 and IPv6 full-tunnel traffic and
split-prefix positive/negative traffic. The server's IPv6 path is routed with
an explicit upstream return route and no NAT66; a saved route policy does not
configure that upstream network for the operator.
The embedded operator page offers these exports from the client editor only
after an explicit action. Closing the editor clears its displayed artifact.

For an in-person or separately delivered share, create an enrollment link with
`POST /api/v1/clients/<client-id>/enrollment-links`. The request requires the
administrator session, exact configured `Origin`, and CSRF token. An optional
`expires_in_seconds` selects a lifetime from 1 second through 24 hours; the
default is 600 seconds. The response contains the capability ID, expiry, and a
share URL whose 256-bit URL-safe token exists after `#token=` only. The raw
token is never stored: SQLite retains its SHA-256 digest.

The recipient opens the link in a browser. The embedded page does not consume a
capability on GET; its script reads the fragment, removes it from browser
history, and sends a small same-origin JSON POST. The first correct consume
returns the config once. Wrong, expired, revoked, deleted-client, and already
consumed capabilities return the same unavailable response. A separate
per-peer/global limiter runs before the worker looks up a capability.

Create and revoke actions are in the secret-safe audit trail. The token and
configuration are never audit fields. The public enrollment page and consume
response use the service's no-store and no-referrer security headers. No CORS
headers are emitted. The operator page displays a newly created link with its
expiry and copy/revoke actions. The raw link is held in page memory only and is
cleared when the client editor closes; deliver it over an approved private
channel.

Each client can hold at most eight live capabilities. Startup and capability
creation prune consumed, revoked, and expired capability rows older than seven
days. Their audit events remain, subject to the bounded 10,000-event audit
retention policy documented in [product management](../architecture/product-management.md).
