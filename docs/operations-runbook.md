# Operations and recovery runbook

This guide covers the currently available state and network commands. Examples
use the Linux default state and socket paths; replace them with the paths used
by your processes. A supported product installer and transactional self-update
are not implemented. Apple silicon macOS server publication is
maintainer-authorized under ADR-014; a published support claim still waits on
C015 and C005 closure. Darwin self-update is unavailable.

## Protect the state database

The database and its backups contain VPN keys, password verifiers, sessions,
and enrollment digests. Keep them owner-only in a protected directory. Use the
online backup command rather than copying a live SQLite file:

```sh
wg-basic state backup /var/lib/wg-basic/backups/before-maintenance.db \
  --state /var/lib/wg-basic/state.db
wg-basic state verify /var/lib/wg-basic/backups/before-maintenance.db
```

The destination must not already exist. See
[state backup and restore](state-backup-restore.md) for path requirements and
recovery behavior.

## Check current state

```sh
wg-basic state status --state /var/lib/wg-basic/state.db
wg-basic network status --state /var/lib/wg-basic/state.db
wg-basic doctor --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock --json
```

`network status` reports whether networking is enabled and the last converged
generation. `doctor` checks state and the typed `netd` backend. Run it as an
account that `netd` authorizes.

## Disable networking

`serve` and the standalone network command cannot hold the state lease at the
same time. Stop `serve` cleanly, keep `netd` available, then disable the network:

```sh
wg-basic network disable --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic network status --state /var/lib/wg-basic/state.db
```

The command commits the disabled state and attempts to apply it. If the result
says it is not enforced or cannot be confirmed, do not assume traffic has
stopped. Check `netd`, retry reconciliation, and confirm the converged
generation before relying on the disable or purging state:

```sh
wg-basic reconcile --state /var/lib/wg-basic/state.db \
  --socket /run/wg-basic/netd.sock
wg-basic network status --state /var/lib/wg-basic/state.db
```

## Purge state

Purge is destructive. Back up and verify the database first. Stop `serve`, keep
`netd` available, and confirm that networking is disabled and converged. Get
the installation ID from `state status`, then preview the exact paths:

```sh
wg-basic state purge --dry-run \
  --confirm-installation-id '<installation-id>' \
  --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock
```

If the preview is correct, repeat the command without `--dry-run`. Purge also
requires a fresh read-only `netd` plan proving that owned networking is gone.
It removes only verified wg-basic state and recovery artifacts. It preserves
separate operator backups and configuration. Lock files may remain so a later
process cannot accidentally lock a different inode.

## Restore a backup

Restore is offline. Stop every process that can write the database, then follow
the [restore procedure](state-backup-restore.md). A failed restore leaves the
current database in place. After a successful restore, start the normal
management process and confirm the state and network have converged before
relying on service.

## Administrator password

After signing in to the management UI, use **Account** to change the local
administrator password. The change revokes other browser sessions but keeps the
session you used. For break-glass recovery when the UI is unavailable, use
`wg-basic admin set-password --password-stdin`; that command still revokes **all**
sessions.

## Prometheus scrape

Prometheus exposition is **disabled by default**. Enable it from the signed-in
management API (`PATCH /api/v1/metrics-settings` with
`{"prometheus_enabled": true}` / `{"json_metrics_enabled": true}` and optional
`set_bearer_password`). When enabled
**without** a Bearer password, only **loopback** peers may scrape
`GET /metrics/prometheus`. When a Bearer password is set, every scraper must send
`Authorization: Bearer <password>`; session cookies are **not** accepted.

Example `prometheus.yml` job (Bearer secret configured):

```yaml
scrape_configs:
  - job_name: wg-basic
    metrics_path: /metrics/prometheus
    scheme: http
    static_configs:
      - targets: ['127.0.0.1:8000']
    authorization:
      type: Bearer
      credentials: '<metrics-bearer-password>'
```

Disabled scrape returns HTTP **400** with body `metrics not enabled`. Scrape
floods use a dedicated admission limiter (separate from login and `/healthz`);
an exhausted budget returns **503** `unavailable`.

## JSON metrics scrape

JSON metrics are **disabled by default**, with an independent
`json_metrics_enabled` flag. Enable from the signed-in management API
(`PATCH /api/v1/metrics-settings` with `{"json_metrics_enabled": true}`). Bearer
password and loopback policy are **shared** with Prometheus: one optional
`set_bearer_password` gates both surfaces.

Example loopback scrape (no Bearer password configured):

```sh
curl -fsS http://127.0.0.1:8000/metrics/json
```

Example with Bearer secret:

```sh
curl -fsS -H "Authorization: Bearer <metrics-bearer-password>" \
  http://127.0.0.1:8000/metrics/json
```

Disabled JSON scrape returns HTTP **400** with body `metrics not enabled`. The
response is `application/json` with aggregate peer counts and a bounded `clients`
array (public keys and endpoints are included as value fields, not Prometheus labels).

## IPv6 considerations

Linux IPv6 forwarding is host-global. Enabling a policy that requires it sets
the host forwarding control to `1`, and disabling the wg-basic network does not
turn it off. Plan the upstream route and return path for the tunnel prefix.
wg-basic does not perform NAT66. Client route settings describe what goes into
the exported client configuration; they do not configure upstream routers.
See [client configuration and enrollment](client-enrollment.md) before
changing client routes.

## Account password and TOTP

Signed-in operators manage credentials from the **Account** pane in the
management UI or from the HTTP API under `/api/v1/account`.

- **Password change:** `POST /api/v1/account/password` with `current_password`
  and `new_password` (Host + exact Origin + CSRF). Sibling sessions are revoked;
  the completing session stays valid.
- **Enable TOTP:** `POST /api/v1/account/totp/begin` (returns QR + otpauth URI),
  then `POST /api/v1/account/totp/confirm` with the six-digit code.
- **Disable TOTP:** `POST /api/v1/account/totp/disable` with `current_password`
  and a valid authenticator code.

With TOTP enabled, login is two steps: password, then `POST /api/v1/login/totp`
with the `pre_session_token` from the password response and the authenticator
code. Pre-sessions expire in five minutes and are single-use.

`wg-basic admin set-password` remains break-glass recovery and does not require
TOTP. It revokes every session.

## Generic OIDC sign-in

Optional generic OIDC (Auth M003) lets operators sign in through an external
OpenID provider instead of the local password. It complements — it does not replace
— break-glass `wg-basic admin set-password`.

**Prerequisites**

- Canonical origin must be **HTTPS** (reverse proxy in front of the loopback
  listener). OIDC cannot be enabled on plain HTTP loopback.
- At the IdP, register a confidential client and allow the authorization code flow
  with PKCE. Token endpoint authentication must accept `client_secret_post` (client
  id and secret in the POST body).

**Redirect URIs to register at the IdP**

Replace `{canonical_origin}` with the configured value (e.g. `https://vpn.example.com`):

| Purpose | Redirect URI |
| --- | --- |
| Login | `{canonical_origin}/api/v1/auth/oidc/callback` |
| Account link (signed-in) | `{canonical_origin}/api/v1/auth/oidc/link/callback` |

**Configure the appliance**

1. Sign in with the local administrator password.
2. Open **Account** → **OIDC provider**, or use `GET` / `PATCH /api/v1/auth/oidc/settings`.
3. Set issuer URL, client id, client secret, and optional button label; check
   **Enable OIDC sign-in** only after HTTPS canonical origin is in place.
4. The login page calls `GET /api/v1/auth/oidc/public` and shows **Sign in with OIDC**
   when enabled.

**Operator linking**

An already-signed-in administrator can bind the IdP subject to the local principal
with `GET /api/v1/auth/oidc/link` (session required). After a successful link
callback the UI returns to `/` with `?oidc_link=ok`.

**Failure behaviour**

Rejected `state`, unknown codes, IdP outages, and throttled callbacks refuse without
naming the cause (`401` / `403` / `429` / `503` families per route). Qualification
lives in `tests/oidc_auth.rs` against a loopback fake IdP.

## Google, GitHub, allow-list auto-register, and password auth (M004)

Auth M004 adds **Google** (OIDC) and **GitHub** (OAuth2 + PKCE), a unified login
advertisement at `GET /api/v1/auth/public`, IdP policy in `GET`/`PATCH
`/api/v1/auth/idp/policy`, and optional **disable password authentication** once at
least one enabled administrator has a linked external identity.

**Redirect URIs**

| Provider | Login callback | Link callback |
| --- | --- | --- |
| Generic OIDC | `{origin}/api/v1/auth/oidc/callback` | `{origin}/api/v1/auth/oidc/link/callback` |
| Google | `{origin}/api/v1/auth/google/callback` | `{origin}/api/v1/auth/google/link/callback` |
| GitHub | `{origin}/api/v1/auth/github/callback` | `{origin}/api/v1/auth/github/link/callback` |

Google uses the standard issuer (`https://accounts.google.com`) by default; qualification
may point the stored issuer at a loopback fake. GitHub uses the configured `oauth_host`
(default `https://github.com`).

**IdP policy (`/api/v1/auth/idp/policy`)**

| Field | Default | Notes |
| --- | --- | --- |
| `auto_register` | `false` | When `true`, unknown IdP emails may create a new **full administrator** principal. |
| `allowed_domains` | empty | Non-empty list: case-insensitive domain match required for login/register. Empty + `auto_register` true allows any IdP email — **high risk**; set domains in production. |
| `auto_launch` | empty | Provider key (`oidc`, `google`, `github`) for optional login auto-redirect; append `?auto_launch=false` to escape. |
| `password_auth_enabled` | `true` | Set `false` only when ≥1 enabled principal has an IdP link; otherwise the API refuses (no change). |

Linking by matching email to an existing principal works when `auto_register` is false.

**Recovery when password login is disabled**

- If every IdP is also disabled, the login UI shows CLI recovery text only (no HTTP bootstrap).
- On the host: `wg-basic admin set-password --password-stdin` **re-enables** password auth and revokes all sessions, same as today.

Qualification: `tests/oauth_m004.rs` (allow-list, auto-register, password disable, Google authorize start, CLI re-enable).
