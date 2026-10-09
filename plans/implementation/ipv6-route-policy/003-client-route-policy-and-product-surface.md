# IPv6 M003 — Client Route Policy and Product Surface

Status: active

Repository baseline: `306ec64` (M002 implementation head; M002 strict closure
and hosted evidence are recorded in `plans/closure/ipv6-route-policy/002-status.md`).

Source roadmap:

- `plans/subsystems/ipv6-route-policy-roadmap.md#7-m003--client-route-policy-and-product-surface`
- `plans/002-long-term-roadmap.md#13-phase-11--ipv6-and-route-policy-production-qualification`

Canonical requirements and decisions:

- `plans/000-long-term-specification.md#9-host-networking-ownership`
- `plans/000-long-term-specification.md#11-reconciliation-model`
- `plans/adr/001-linux-native-control-plane.md`
- `plans/adr/004-product-management-enrollment-and-api-semantics.md`
- `plans/adr/007-ipv6-forwarding-ownership.md`
- M001 closure: `plans/closure/ipv6-route-policy/001-status.md`
- M002 closure: `plans/closure/ipv6-route-policy/002-status.md`

Primary class: capability / product surface

Hard dependencies:

- M001 strict closure: durable dual-stack tunnel assignment and peer state.
- M002 strict closure: routed IPv6 forwarding and firewall ownership.

## 1. Objective

Complete the authenticated product boundary for explicit dual-family client
routes. Support IPv6 full tunnel (`::/0`) and split routes alongside the
existing IPv4 route choices. Persist and validate route intent, expose it
through the authenticated API and embedded UI, and render exact family-correct
WireGuard `AllowedIPs`, endpoint, and DNS values. A tunnel address alone must
never select a client route.

## 2. Explicit non-goals

- Changing the server's forwarding, firewall, upstream-route, or NAT policy.
- NAT66, arbitrary policy routing, DNS service operation, endpoint discovery,
  or DDNS.
- Per-client server-side firewall policy or more than one managed server.
- Inferring a default route from IPv6 address allocation or server setup.
- Changing existing IPv4-only defaults, exported configs, or API behavior.
- Claiming end-to-end IPv6 traffic qualification; that is M004.

## 3. Repository evidence at the baseline

- `ClientRoutePolicy` already stores typed family-capable prefixes in SQLite.
- Client and server IPv6 tunnel addresses, M002 forwarding, and the routed
  firewall path are implemented and qualified.
- Product setup, client create/update APIs, generated configs, DNS values, and
  advertised endpoints already have the underlying typed fields. Advertised
  endpoints accept bracketed IPv6 literals; DNS values are `IpAddr` values.
- The client UI has a general route-prefix field, but it does not present clear
  IPv6 route choices or explain the dependency on an assigned IPv6 address and
  server IPv6 routing.
- Route policy validation does not yet enforce bounded, unique prefixes or
  reject IPv6 routes for clients without IPv6 tunnel state.
- Server-side peer `AllowedIPs` contain client tunnel host prefixes, while
  client route policy is separately used for exported client `AllowedIPs`.

## 4. Invariants

1. Route intent remains explicit in desired state. Assigning an IPv6 address
   does not add `::/0` or any other client route.
2. Client route policy and server-side peer `AllowedIPs` remain separate.
   Server peers select the client's assigned tunnel addresses; exported client
   configs use only the selected client routes.
3. IPv6 routes require a configured managed server IPv6 pool and an IPv6
   address assigned to that client. IPv4-only clients and installations remain
   valid with the existing defaults.
4. Route prefixes are typed, normalized, unique, and bounded. No command, raw
   configuration, or filesystem input crosses the privileged boundary.
5. Unsafe or unsupported policy is rejected before the generation-checked
   transaction commits; a failed update does not partially change settings.
6. API mutations retain session, CSRF, Origin, authorization, and desired
   generation checks.
7. IPv6 endpoint literals render with exactly one bracket pair; IPv4 and DNS
   endpoint rendering remains unchanged. DNS values retain their IP family.

## 5. Ordered work packages

### A. Validate persisted route policy

- Set a documented upper bound for route prefixes and reject duplicate or
  invalid normalized prefixes.
- Allow the explicit family default routes `0.0.0.0/0` and `::/0`; reject
  unspecified and multicast prefixes in other forms.
- Validate global defaults against server tunnel configuration and each
  per-client policy against that client's assigned addresses.
- Preserve old stored IPv4 route policies and empty route-policy behavior.
- Do not add a migration unless implementation evidence demonstrates a new
  persistence value is required.

### B. Enforce policy at product and HTTP boundaries

- Apply validation to server setup defaults, client creation, and client
  updates before persistence or generation advancement.
- Reject IPv6 routes if the managed server lacks an IPv6 pool or the selected
  client has no IPv6 assignment.
- Keep the existing authenticated request envelope and bounded response
  shapes; do not add an unauthenticated route or route-preview endpoint.
- Ensure pending network application is reported through the existing product
  mutation receipt and never described as enforced prematurely.

### C. Render dual-family client configuration

- Render the chosen route prefixes exactly into client `AllowedIPs` in stable
  order, preserving the current IPv4 output when policy is unchanged.
- Keep assigned IPv4/IPv6 addresses separate from `AllowedIPs`.
- Verify bracketed IPv6 advertised endpoints, IPv6 DNS entries, escaping,
  redaction, and deterministic output with unit/product/API tests.
- Reject config export if its persisted route policy is invalid rather than
  emitting a misleading file.

### D. Expose usable route choices in the embedded UI

- Provide explicit independent IPv4 and IPv6 route controls for no route,
  full tunnel, and split prefixes; keep existing split-prefix editing
  accessible without adding a frontend build system.
- Explain that IPv6 routes require IPv6 server and client tunnel addresses and
  a functioning routed IPv6 egress policy.
- Do not silently turn on IPv6 routes when setting up an IPv6 address.
- Keep authentication/session and CSP constraints unchanged.

### E. Verify compatibility and document behavior

- Add unit tests for bounds, family validation, explicit full/split selection,
  and old IPv4-only defaults.
- Add product and authenticated API tests for accepted/rejected settings,
  generation behavior, export, DNS, and IPv6 endpoint formatting.
- Verify default IPv4 exported configuration is unchanged for representative
  existing client states.
- Update `architecture/product-management.md`,
  `architecture/domain-model.md`, `architecture/state-store.md`,
  `architecture/testing-qualification.md`, `docs/client-enrollment.md`, and
  `docs/development.md` to describe the explicit route contract.
- Do not claim routed client traffic until M004's rootful evidence is complete.

## 6. Failure, retry, and compatibility contract

- Invalid route policy fails before a durable mutation; generation and existing
  client settings remain unchanged.
- Old IPv4-only policies reopen and export identically.
- Removing IPv6 routes or changing route policy affects only client config and
  corresponding desired client peer reconciliation; it does not alter server
  forwarding policy or host routes.
- API timeout or pending application follows existing product receipt
  semantics; the committed desired route remains authoritative for retry.
- Config export uses persisted desired state and reports validation failure
  without exposing private material in diagnostics.

## 7. Security and product effects

The HTTP service continues to hold no network privilege. No new netd operation
is expected: route selection changes the generated client configuration, while
M001/M002 already own server tunnel addresses, routes, forwarding, and firewall
state. The route schema must not permit arbitrary netlink, system routing, or
server-side firewall instructions.

## 8. Acceptance criteria

1. IPv6 full tunnel and IPv4/IPv6 split routes are explicit and persist across
   reopen and backup/restore.
2. IPv6 route policy is rejected without both managed server IPv6 tunnel state
   and a client IPv6 assignment.
3. IPv6 address assignment alone does not change route policy.
4. Generated `AllowedIPs` contain selected client routes only; server peer
   `AllowedIPs` remain assigned tunnel host prefixes.
5. IPv6 endpoint and DNS values render correctly; existing IPv4 output is
   unchanged when its policy is unchanged.
6. Authenticated create/update/setup APIs reject invalid policy without
   advancing generation; valid requests retain normal pending/enforced
   receipts.
7. Operator UI exposes both families without enabling routes implicitly.
8. Full Rust gates and hosted CI pass; M003 closure maps each criterion to
   exact evidence and has no unresolved high/medium finding.

## 9. Stop conditions and successor handoff

Stop and revise the plan if IPv6 routing can only be inferred from address
assignment, if client route policy must be merged into server peer
`AllowedIPs`, if the existing authenticated generation contract cannot reject
invalid policy before commit, or if preserving IPv4-only exported output
requires a breaking change. M004 remains blocked until M003 strictly closes.
