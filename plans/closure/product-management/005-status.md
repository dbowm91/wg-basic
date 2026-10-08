# Product Management M005 Closure — Embedded UI and Phase 8 Qualification

Status: closed.

Implementation commit: `8b20a7c` — `feat: add embedded product management UI`.
Planning baseline: M004 closure at `f5ae276`.
Final implementation head: `8b20a7c`.
Disposition: **closed**. Phase 8 is closed as the first user-facing product boundary.

## Requirement-to-evidence matrix

| Requirement | Evidence |
| --- | --- |
| Buildless embedded operator UI | `index.html`, `app.css`, and `app.js` are compile-time embedded. The page provides login, server setup, dashboard, clients, editor, export/QR/link actions, telemetry and audit. The five assets total 29,811 bytes under the 32 KiB aggregate ceiling. Architecture guards prove no external origins, inline script/style, frontend package/build files, filesystem document root, browser credential storage, or secret console logging. |
| Setup and operator vocabulary | The setup form includes the server address/endpoint/listen port and tunnel prefix with advanced interface, route, egress, forwarding, and NAT fields. Client forms expose labels, addresses, routes, DNS, keepalive, enabled state, and expected lifecycle actions. Operator text does not expose reconciliation, nftables, owner-tag, or process-execution mechanics. |
| Generation conflict handling | Every product mutation sends the generation obtained from the latest API read or mutation receipt. A `409` refreshes server/client state and asks the operator to review; the UI does not retry automatically. Asset guards pin this behavior. Existing HTTP coverage proves stale-generation responses occur before commit. |
| Durable commit versus enforcement | The UI reports pending/degraded create/update operations as saved but still applying. Disable/delete wording explicitly says revocation is not confirmed. A 202 response is retained across the post-mutation refresh, and unavailable telemetry clears old observations instead of presenting stale state as live. |
| Secret artifact handling | Config and QR are requested only after operator action. Config uses a temporary download object URL; QR is fetched from the authenticated same-origin no-store route; dialog close clears rendered artifacts. One-time links are displayed once with expiry, copy and revoke actions, with no browser storage. |
| Bounded live telemetry and audit | Telemetry refreshes every 7 seconds only while an authenticated page is visible, pauses while hidden, and stops on logout. The dashboard displays health, generations, endpoints, client counts, handshake and byte counters. Audit uses the bounded timestamp/event cursor API and renders data using `textContent`. |
| Real product HTTP and kernel E2E | `exported_client_config_establishes_a_real_kernel_handshake` initializes durable state/admin, starts real netd and the HTTP service, logs in, configures the server over HTTP, creates a client, downloads config and QR, creates and consumes a one-time enrollment exactly once, configures a real client namespace, proves a real WireGuard handshake and traffic, reads telemetry/audit over authenticated HTTP, disables and re-enables over HTTP, and deletes the peer over HTTP. The same test checks the embedded UI/CSP, secret-safe audit sequence, and absence of the enrollment token from audit output. Separate HTTP lifecycle coverage proves committed changes remove/restore real kernel peers. |
| Perimeter and browser security properties | Real-wire/service tests cover foreign Host rejection, exact Origin and CSRF requirements, stale generation, no CORS, no-store secret responses, non-consuming enrollment landing, single-use consume, logout, and password-reset session invalidation. Product mutations remain worker-backed and pass through the single response-seal point. No raw execution, host-network mutation, or new protocol operation was added. |
| Runtime footprint and latency | Release `service_footprint` measured combined serve/netd RSS at 13.54 MiB, zero idle CPU ticks over 2 seconds, cold readiness at 66.7 ms, `/healthz` at 679 μs, login at 74.1 ms, and authenticated health at 20.18 ms; figures are medians of five samples. The product fixture measured one HTTP server read at 2.44 ms, client create including reconcile at 79.4 ms, live telemetry at 22.4 ms, setup at 120.4 ms, and the 29,811-byte asset inventory. These product-route figures are single fixture samples, not service-level guarantees. |
| Documentation and Phase 8 disposition | README, development instructions, product-management architecture, HTTP boundary, privilege boundary, client enrollment, overview, and registry/roadmap describe current behavior. Phase 8 is closed; direct TLS, installation/update, multi-user roles, and production IPv6 remain outside this milestone. |

## Verification performed

All commands passed against implementation head `8b20a7c`:

```text
rtk cargo fmt --all -- --check
rtk cargo check --all-targets --locked
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo +1.89.0 check --all-targets --locked
rtk cargo test --locked                         # 493 passed, 24 suites
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration -- --test-threads=1
                                                  # all unit and Linux integration targets passed
rtk sudo -n env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
                                                  # 6 passed
rtk cargo test --release --locked --test service_footprint -- --nocapture
                                                  # 2 passed; footprint and latency figures above
rtk proxy node --check src/http/assets/app.js
rtk git diff --check
```

The combined Linux run exercised the prior network-control, durable ownership,
restart, backup/restore, management HTTP/security, process-level service, and
Phase 8 rootful suites on the same implementation head. The product rootful
fixture uses real namespaces, actual WireGuard devices, and the same HTTP
handlers consumed by the embedded UI.

## Security, ownership, and findings

The UI is an API client, not a second authority: setup, client state, credentials,
generation checks, enrollment, and telemetry remain worker/API responsibilities.
No private key or preshared key enters ordinary client JSON or audit output.
Artifacts remain in transient page memory and are cleared from the editor on
close. The one-time token appears only in the share URL fragment and consume
body; it is absent from audit output. No high, medium, or low finding remains
open.

The product HTTP mutation response does not expose separate database-commit and
reconcile phase timings, so the fixture records end-to-end create latency only;
no production instrumentation was added to split that operation. Direct TLS,
installation/systemd, multi-user roles, and IPv6 product qualification remain
planned outside Phase 8.

Phase 8 M001–M005 is closed. No active or eligible implementation plan remains
in the registry; later distribution work stays proposed behind operational
hardening.
