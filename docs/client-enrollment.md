# Client configuration and enrollment

In the operator UI, choose **Add client**, enter a name, and choose **Create
client**. Open that client's editor from the Clients section. The editor can
export a standard WireGuard configuration, show a QR code for it, or create a
one-time enrollment link.

Configuration files, QR codes, and enrollment links contain credentials. Share
them only through a private channel and store downloaded files securely.

## Export a configuration

Choose **Download config** to download the client profile, or **Show QR code**
to display the same configuration as a QR code. The export is generated only
after you request it. Responses use `Cache-Control: no-store`, and closing the
client editor clears the displayed artifact.

A client without an allowed route policy cannot be exported because its
`AllowedIPs` would be unusable. A disabled client can still be exported, but it
will not pass traffic once the disable has been enforced. Check the client
status if you need to confirm revocation.

## Routes, MTU, and preshared keys

IPv4 and IPv6 routes are selected independently. Each family can have no route,
a full-tunnel default route, or split prefixes. IPv6 routes require both a
managed server IPv6 tunnel range and an IPv6 address assigned to the client.
An IPv6 address alone does not enable IPv6 routes. The upstream network must
also provide routed egress and a return route for the tunnel prefix. wg-basic
does not configure upstream routers or use NAT66.

A client MTU from 1280 through 9000 is written to the exported configuration.
An unset MTU omits the line. Changing it does not change the server interface
MTU. The client must re-import the profile to receive route or MTU changes.

You can generate or clear a server-generated preshared key in the client
editor. The key is not shown in the client summary. Changing it changes the
profile, so the client must re-import the updated configuration.

## Client expiration

An optional expiration time disables the client when the management worker's
clock reaches the deadline. The clock is authoritative; wg-basic does not
check whether NTP is configured. Expiration keeps the client row, addresses,
and keys. As with other mutations, confirm that enforcement succeeded if you
need to know exactly when access was revoked.

## Create a one-time enrollment link

Choose **Create one-time link** in the client editor. The default lifetime is
10 minutes. The API also accepts `expires_in_seconds` from 1 second through
24 hours. The response contains a share URL, expiry time, and capability ID.
The token is a 256-bit URL-safe value in the URL fragment. It is not stored in
the database; SQLite stores only its SHA-256 digest.

Use **Copy link** and send the link privately. When the recipient opens it,
the page removes the token from browser history and immediately sends a consume
request. The first valid request consumes the capability and returns the
configuration. The page then offers a **Download configuration** link. Because
the link is consumed when the page loads, ask the recipient to open it only
when ready to download. If they lose access to the page, create a new link.
You can revoke an unused link from the client editor.

Invalid, expired, revoked, deleted-client, and already-used links return the
same unavailable response. Each client can have at most eight live links.
The application prunes consumed, revoked, and expired capability records
older than seven days. Audit events remain subject to the bounded retention
policy.

Creating and revoking links is recorded in the secret-safe audit trail. The
raw token and client configuration are never audit fields. The page uses
no-store and no-referrer headers and does not emit CORS headers.
