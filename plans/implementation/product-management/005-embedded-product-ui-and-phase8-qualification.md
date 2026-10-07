# Product Management M005 — Embedded Product UI and Phase 8 Qualification

Status: blocked on Product Management M004 closure

Source roadmap:

- `plans/subsystems/product-management-enrollment-ui-roadmap.md#9-m005--embedded-product-ui-and-phase-8-qualification`

Canonical architecture:

- `plans/adr/004-product-management-enrollment-and-api-semantics.md`

Primary class: product closure / end-to-end qualification

Hard dependency: Product Management M004 strict closure.

## 1. Objective

Deliver the first complete wg-easy-like operator experience using the embedded, buildless UI and close Phase 8.

The UI consumes the API; it does not duplicate allocation, validation, generation, enrollment, or security logic.

## 2. UI technology

Extend the current embedded HTML/CSS/JS assets.

Requirements:

- no Node;
- no package manager;
- no bundler;
- no React/Vue/Svelte;
- no CDN;
- no external fonts/scripts/styles;
- no filesystem document root;
- existing CSP remains strict unless a narrowly documented change is unavoidable.

Prefer small ES modules if splitting JavaScript improves maintainability; embed each file explicitly.

## 3. Application views

Required user flows:

### Login

Reuse Phase 7 session surface.

### Setup

Shown only after authenticated login when no primary server exists.

Fields:

- interface name;
- tunnel IPv4 prefix;
- server address with sensible default;
- listen port;
- advertised endpoint host/port;
- egress interface;
- NAT/forwarding;
- default client route policy.

Explain that admin bootstrap is local CLI and already complete.

### Dashboard

Show:

- service/network health;
- server endpoint/listen info;
- current generation/convergence;
- enabled/disabled client counts;
- recent telemetry summary.

### Clients

List:

- label;
- assigned address;
- enabled;
- latest handshake;
- RX/TX;
- action controls.

### Client detail/edit

- label;
- route policy;
- DNS;
- keepalive;
- enabled;
- address;
- config download;
- QR;
- one-time share link;
- delete.

### Audit/status

Bounded recent mutation history and safe status.

## 4. Generation-conflict UX

The UI caches the generation returned by reads.

Every mutation sends it.

409 behavior:

- do not silently retry;
- refresh current state;
- tell operator state changed;
- require/replay explicit user intent only through a fresh interaction.

No last-write-wins hidden overwrite.

## 5. Committed-but-not-enforced UX

202 behavior is load-bearing.

For create/update:

- show “saved; network application pending/degraded”.

For disable/delete:

- show stronger warning such as “saved, but network access has not been confirmed revoked”.

Do not optimistically remove warning until convergence/telemetry confirms.

## 6. Secret artifact UX

Config/QR:

- shown/downloaded only on explicit action;
- never stored in localStorage/sessionStorage;
- no console logging;
- close/clear modal DOM content when dismissed where practical.

One-time link:

- raw share token displayed once;
- copy button;
- expiry shown;
- revocation action;
- UI explains the link reveals VPN credentials once.

Do not embed client config in ordinary client-list JSON.

## 7. Telemetry polling

Use bounded polling only while relevant authenticated page is visible.

Suggested interval: 5–10 seconds.

Pause on hidden document.

Stop on logout/navigation.

No WebSocket solely for charts.

Charts are optional; numeric RX/TX and handshake state are sufficient for Phase 8 closure.

## 8. First product E2E

Build a real rootful fixture driven through HTTP and the same API used by the UI.

Required sequence:

1. initialize DB/admin;
2. start real netd + serve;
3. login;
4. POST setup;
5. create client;
6. obtain ordinary config;
7. obtain QR;
8. create one-time link;
9. configure a real client namespace from exported config values;
10. prove WireGuard handshake and traffic;
11. telemetry endpoint reports handshake/RX/TX;
12. disable client through HTTP;
13. prove access stops/peer removed;
14. enable client;
15. prove access resumes after handshake;
16. consume one-time enrollment exactly once;
17. delete client;
18. prove peer removed/access revoked;
19. audit contains secret-safe action sequence.

This fixture must not bypass worker/state APIs for product mutations.

## 9. Browser/security E2E

Against real child process, assert:

- foreign Host denied on product routes;
- unsafe mutation without Origin denied;
- unsafe mutation without CSRF denied;
- stale generation conflict;
- secret routes no-store;
- one-time GET preview non-consuming;
- one-time fragment token absent from server request logs;
- logout invalidates product access;
- password reset invalidates sessions;
- no CORS.

## 10. Product defaults/UX quality

The default path should require the minimum concepts needed to produce a working tunnel.

Advanced fields should be visually separated.

Do not expose internal terms such as:

- owner tag;
- reconcile plan;
- nftables marker;
- desired-generation CAS

unless in diagnostics.

Use operator terms:

- Server;
- Client;
- VPN address;
- Endpoint;
- Routes;
- DNS;
- Enabled;
- Last handshake;
- Traffic.

Generation conflicts can be described as “configuration changed elsewhere”.

## 11. Accessibility/basic browser support

Without adding a framework:

- semantic labels/form controls;
- keyboard-usable actions;
- visible focus;
- status messages not color-only;
- no hover-only required action;
- reasonable narrow-screen layout for phone QR/enrollment workflows.

No large accessibility framework required.

## 12. Static guards

Add/retain guards for:

- no external origins in assets;
- no Node/npm lock/package files;
- no direct secret logging;
- no localStorage/sessionStorage for config/enrollment secrets;
- product mutations only through worker;
- all response paths still pass single header seal;
- no CORS;
- no wg-quick hook field anywhere in product API/UI.

## 13. Footprint/performance

Re-run Phase 7 measurements after the full UI/API lands:

- combined serve+netd idle RSS;
- idle CPU;
- cold readiness;
- dashboard safe-read latency;
- create client mutation latency excluding/including reconcile;
- telemetry latency;
- asset total size.

The 30 MiB long-term memory target remains an engineering signal, not permission to weaken correctness.

## 14. Documentation

Update:

- README;
- `architecture/overview.md`;
- `architecture/management-http.md`;
- new `architecture/product-management.md`;
- new `docs/client-enrollment.md`;
- development/rootful product test instructions;
- registry/roadmap.

Document clearly:

- local CLI admin bootstrap;
- authenticated setup wizard;
- loopback/reverse-proxy deployment profile;
- client lifecycle;
- config/QR secrets;
- one-time link semantics;
- 202 enforcement warning;
- IPv4 baseline / IPv6 deferred;
- no direct TLS/install/update yet.

## 15. Acceptance criteria

M005 closes only when:

1. setup→client→export/QR→connect works from UI/API;
2. real exported configuration establishes a real tunnel;
3. telemetry reports real handshake/traffic;
4. disable/delete are proven to revoke when converged;
5. degraded revoke UX is truthful;
6. one-time enrollment consumes once and scanner GET does not consume;
7. audit remains secret-safe;
8. UI is self-contained/buildless;
9. security perimeter remains load-bearing on every mutation route;
10. all Phase 6–8 rootful and routine/MSRV CI pass;
11. no high/medium security/correctness finding remains;
12. docs describe Phase 8 as the first user-facing product closure while Phases 9–12 remain pending.

## 16. Stop conditions

Stop/write corrective if:

- UI needs direct StateStore/netd access;
- exported config cannot drive a real client;
- one-time link leaks raw secret into request URL/logs;
- a committed disable/delete is displayed as revoked before enforcement;
- Phase 8 requires direct TLS or install/systemd to prove product functionality;
- full product UI requires a Node runtime.

## 17. Closure evidence

Record:

- asset inventory/size;
- user-flow screenshots or fixture outputs where appropriate;
- full route inventory;
- real product E2E trace;
- exported-client handshake/traffic;
- disable/re-enable/delete evidence;
- one-time capability matrix;
- security negative matrix;
- audit privacy;
- footprint;
- all CI/MSRV/rootful suites;
- Phase 8 disposition and Phase 9 readiness.
