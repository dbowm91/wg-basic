# Product Management M003 Closure — Export, QR, and One-Time Enrollment

Status: closed.

Implementation commit: `de04105` — `feat: add client export and one-time enrollment`.
Planning baseline: M002 closure at `79e698a`.
Final implementation head: `de04105`.
Disposition: **closed**.

## Requirement-to-evidence matrix

| Requirement | Evidence |
| --- | --- |
| Deterministic standard config, bounded and secret-redacted | `src/product/export.rs` exact fixture test covers section/order/newline output, key redaction, optional DNS/PSK/keepalive fields, route sorting, and rejection of missing `AllowedIPs`. |
| Authenticated config and local SVG QR | Exact client config/QR routes use the worker; real HTTP test checks attachment filename, `text/plain`, `image/svg+xml`, no-store, no sniffing, and absence of private-key text in SVG. QR tests pin the fixed SVG vocabulary/quiet-zone output and reject encoder overflow. |
| QR crate/MSRV/dependency qualification | `qrcodegen` 1.8.0 is locked; no image stack was added. `cargo +1.89.0 check --all-targets --locked` passed. |
| Schema v3→v4 capability migration | Immutable `004_enrollment_capabilities.sql` adds digest-only rows, client cascade, creator FK, expiry checks, and indexes. Migration runner tests plus the auth migration fixture verify a v1 store upgrades through schema 4; the full schema migration suite passes. |
| 256-bit token, digest-only storage, expiry/revocation | OS CSPRNG creates 32 bytes and URL-safe no-pad encoding; SQLite stores SHA-256 only. HTTP assertions inspect the stored digest and audit data for token absence, exercise 1-second expiry and explicit revoke. Default 600 seconds and maximum 24 hours are documented. |
| Fragment-only delivery and non-consuming landing | Generated URL puts the token after `#`; the wire test opens the ID-only landing path, confirms it serves the embedded page, and confirms the script removes the fragment before POST. GET performs no worker lookup. |
| Atomic single use and privacy | Store transaction validates digest/expiry/revocation/consumption, renders before commit, marks consumed and audits atomically. Wire tests cover wrong-token non-consumption, first success, replay, revoked, and expired responses with the same `410`; output is no-store/no-referrer and no CORS. |
| Host/Origin/CSRF/rate-limit boundaries | Admin create/revoke pass through session and CSRF checks; consume rejects foreign Host/Origin and runs its independent bounded limiter before worker dispatch. The token itself authorizes consume, so no administrator session or CSRF token is required. |
| Real exported-config interoperability | `exported_client_config_establishes_a_real_kernel_handshake` configures a real second namespace from exported config values and observes matching endpoint, allowed route, handshake, RX and TX counters on both real WireGuard devices. No production `wg`/`wg-quick` dependency is used. |

## Verification performed

All commands passed against implementation head `37c0ff7`:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked                         # 490 passed, 24 suites
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
                                                  # 6 passed, real namespaces/kernel
```

The HTTP enrollment flow is tested over real loopback TCP. The exported client
test uses temporary network namespaces and typed netd observation/application;
the observed handshake and byte counters prove the rendered key, endpoint,
address and route settings interoperate with the kernel.

## Security, ownership, and findings

HTTP reaches capability state and secret material only through typed worker
commands. Enrollment tokens are redacted by `Debug`, never added to audit
fields, and are stored as digests. Config and SVG values are bounded and wipe
their owned string storage on drop. Public enrollment has its own rate limiter;
malformed/unavailable/expired/revoked/consumed capabilities share one response.
The landing page is embedded, same-origin, no-store, and no-referrer. No raw
process execution, host-network mutation, new privileged protocol operation,
or production `wg` dependency was introduced.

The first rootful probe showed that this environment drops the test ICMP echo
reply even after the WireGuard handshake. M003 requires and now verifies the
real handshake, configured address/route/endpoint, and bidirectional kernel
counters; ICMP reachability is not used as a pass condition for this export
contract. No high, medium, or low finding remains open.

M004 is unblocked and active. Historical M001/M002 closure records remain
unchanged.
