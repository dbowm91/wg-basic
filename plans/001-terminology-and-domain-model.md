# wg-basic Canonical Terminology and Domain Model

Status: normative companion to `plans/000-long-term-specification.md`

This document defines the language wg-basic implementation plans, storage schemas, IPC/API types, tests, logs, UI labels, and operator documentation MUST use.

## 1. Naming rules

1. Durable objects MUST have stable typed identifiers independent of Linux interface names or database row numbers.
2. A kernel interface name is a locator, not durable identity.
3. Desired configuration and observed kernel state are distinct.
4. Server-side cryptokey routing and generated client route policy are distinct.
5. A peer is a WireGuard cryptographic peer; a client is a managed peer plus enrollment/export metadata.
6. Host-owned and wg-basic-owned network resources MUST never be described interchangeably.
7. A plan is a proposed reconciliation; an apply result is evidence of mutation; observed state is post-apply kernel evidence.

## 2. Top-level relationships

```text
Installation
|-- ManagementService
|   |-- Administrators / Sessions
|   |-- DesiredStateStore
|   `-- UI / API
|-- NetworkService
|   |-- PrivilegedProtocol
|   |-- WireGuardController
|   |-- LinkAddressRouteController
|   `-- FirewallForwardingController
|-- ManagedInterfaces
|   `-- ManagedPeers / ManagedClients
|-- AuditEvents
`-- Release / Update State
```

## 3. Installation

An **installation** is one wg-basic administrative and host-network ownership domain on one Linux host.

It owns:

- one durable state database;
- one management-service identity;
- one network-service identity;
- zero or more managed WireGuard interfaces;
- wg-basic-owned nftables state;
- operator configuration;
- installation/update metadata.

An installation is not a WireGuard interface.

Suggested identifier: `InstallationId`.

## 4. Management service

The **management service** is the unprivileged process role that owns HTTP/API/UI behavior, durable application state, authentication, client enrollment/export, and orchestration of privileged reconciliation.

It MUST NOT directly become the public privileged network mutation authority.

## 5. Network service

The **network service** is the privileged local process role that owns kernel/network mutations and live network observation.

It receives a narrow typed protocol over local IPC and validates privileged operations independently.

Preferred process shorthand: `netd`.

Do not use `daemon` as a synonym for the entire product when ownership matters; both management and network roles may be daemons.

## 6. Managed interface

A **managed interface** is one logical WireGuard server interface owned by wg-basic.

It has:

- stable application ID;
- kernel interface name;
- server key identity;
- listen port;
- tunnel addresses;
- MTU policy;
- advertised endpoint configuration;
- managed peer set;
- lifecycle state.

Suggested identifier: `InterfaceId`.

The interface name such as `wg0` or `wgb0` is a kernel locator and MAY change without changing `InterfaceId`.

## 7. Interface locator

An **interface locator** is the current kernel-facing name/index used to address a link.

Examples:

- Linux interface name;
- kernel ifindex.

A locator is observed/mutable state, not durable identity.

## 8. WireGuard peer

A **WireGuard peer** is one cryptographic peer entry configured on a WireGuard interface.

A peer owns:

- public key;
- optional preshared key reference;
- server-side AllowedIPs;
- optional persistent keepalive;
- observed endpoint;
- observed latest handshake;
- observed RX/TX counters.

The peer private key generally belongs to the client and is not part of the kernel server peer record.

Suggested identifier for a managed peer: `PeerId`.

## 9. Managed client

A **managed client** is wg-basic's administrative object for a WireGuard peer intended for an end-user/device.

It includes the associated `PeerId` plus:

- label/display metadata;
- assigned tunnel address;
- client-side route policy;
- optional DNS policy;
- enrollment/export state;
- enabled/revoked lifecycle;
- secret reference when wg-basic generated and retains client private key material.

A managed client is not the same thing as a kernel peer snapshot.

Suggested identifier: `ClientId`.

## 10. Server-side AllowedIPs

**Server-side AllowedIPs** are WireGuard cryptokey-routing prefixes configured on the server peer.

For an ordinary road-warrior client assigned one address, this SHOULD normally be a host route such as `10.8.0.2/32`.

They determine which source/destination prefixes are associated with that peer in the WireGuard interface.

## 11. Client route policy

A **client route policy** defines which destinations appear in the generated client configuration `AllowedIPs`.

Examples:

- full tunnel: `0.0.0.0/0`, optionally `::/0`;
- split tunnel: selected private/application prefixes.

It MUST NOT be conflated with server-side AllowedIPs.

## 12. Tunnel address

A **tunnel address** is an address assigned inside the WireGuard overlay.

Examples:

- server `10.8.0.1/24`;
- client `10.8.0.2/32`.

The allocator MUST reason in terms of address family, subnet, host assignment, conflicts, and reservations.

## 13. Advertised endpoint

The **advertised endpoint** is the host/port inserted into generated client configurations.

It may be:

- explicit DNS name;
- explicit public IP;
- explicit private/LAN IP;
- a later discovery result when endpoint discovery is added.

It is not the observed roaming endpoint of a peer.

## 14. Observed peer endpoint

The **observed peer endpoint** is the source IP/port last reported by the kernel for a connected WireGuard peer.

It is live telemetry and MUST NOT overwrite the client's configured server endpoint.

## 15. Desired state

**Desired state** is the durable configuration wg-basic intends to own.

It contains managed interface, peer, routing, forwarding, and firewall policy.

Desired state is authoritative application configuration.

## 16. Observed state

**Observed state** is a point-in-time kernel/host snapshot relevant to wg-basic ownership.

It includes:

- WireGuard interface/peer state;
- link state;
- addresses;
- routes;
- owned nftables objects;
- relevant forwarding facts;
- live peer telemetry.

Observed state is evidence, not configuration.

## 17. Reconciliation plan

A **reconciliation plan** is an ordered typed difference between validated desired state and observed state.

A plan contains only mutations wg-basic is authorized to own.

Suggested identifier: `ReconcilePlanId` for durable/audited plans if persisted; ephemeral implementations MAY use a digest instead.

## 18. Reconciliation

**Reconciliation** is the sequence:

```text
observe
 -> validate
 -> diff
 -> plan
 -> apply
 -> re-observe
 -> verify
```

A no-op convergence is a successful reconciliation with zero mutations.

## 19. Mutation

A **mutation** is one typed privileged operation that changes kernel/host state.

Examples:

- create WireGuard link;
- set WireGuard device configuration;
- add/remove interface address;
- add/remove route;
- replace wg-basic-owned nftables table/chain/set/rules;
- enable required forwarding state according to the accepted ownership policy.

A mutation is not an arbitrary command string.

## 20. Ownership proof

An **ownership proof** is the evidence required before mutating/removing an existing host resource.

The exact evidence depends on resource type and may include:

- durable managed identifier and expected locator;
- dedicated nftables table namespace;
- exact link type/name/state match;
- route tuple matching desired wg-basic state;
- installation marker/state;
- previously recorded application receipt.

If ownership is uncertain, the mutation MUST fail closed.

## 21. Network capability snapshot

A **network capability snapshot** is a bounded observation of whether the host supports the prerequisites for a requested operation.

It may include:

- Linux/kernel identity;
- WireGuard Generic Netlink family availability;
- RTNETLINK capabilities;
- nftables/netfilter availability;
- effective process capabilities;
- namespace/test support;
- required filesystem/runtime paths.

It is diagnostic/decision input, not authorization by itself.

## 22. Privileged protocol

The **privileged protocol** is the versioned local IPC contract between management service and network service.

The protocol contains typed requests/responses and MUST NOT expose generic process execution or arbitrary kernel message forwarding.

## 23. Firewall policy

A **firewall policy** is the wg-basic-owned declarative filter/NAT intent for managed tunnel traffic.

The initial policy should represent:

- forwarding allow/deny requirements;
- established/related return traffic as needed;
- tunnel-to-egress NAT/masquerade when selected;
- optional explicit ingress/listen allowances only where wg-basic owns them.

It is not raw nftables source text.

## 24. Firewall namespace

The **firewall namespace** is the dedicated nftables table/object space wg-basic owns, such as `inet wg_basic`.

wg-basic MUST NOT treat the entire host ruleset as its namespace.

## 25. Forwarding policy

A **forwarding policy** states whether IP forwarding is required and how wg-basic will handle a host-wide setting it cannot safely claim exclusively.

It is distinct from firewall forwarding rules.

## 26. Network backend

A **network backend** is an internal implementation of one typed kernel control boundary.

Expected backend families:

- `WireGuardBackend`;
- `LinkRouteBackend`;
- `FirewallBackend`;
- `ForwardingBackend`.

Initial production implementations are Linux-native.

A backend is not a user-selectable arbitrary command adapter.

## 27. Enrollment artifact

An **enrollment artifact** is a secret-bearing client configuration presentation.

Forms include:

- standard WireGuard configuration text;
- QR representation;
- single-use configuration URL/capability.

Enrollment artifacts MUST be treated as credentials.

## 28. One-time enrollment capability

A **one-time enrollment capability** is a high-entropy, expiring, single-use authorization token permitting retrieval of one enrollment artifact.

It is not an administrator session token.

## 29. Secret reference

A **secret reference** is an application-level handle to secret material whose ordinary display/debug form contains no secret bytes.

Examples include references to:

- server private key;
- client private key;
- preshared key;
- session signing key.

## 30. Admin principal

An **admin principal** is an authenticated management actor.

The initial product MAY support one local administrator identity. Future multi-admin roles MUST extend this concept rather than embedding authorization in HTTP routes.

Suggested identifier: `PrincipalId`.

## 31. Session

A **session** is an authenticated management-service login context.

It is not a WireGuard session; WireGuard is connectionless and wg-basic MUST NOT use management `session` terminology for a VPN peer handshake.

## 32. Live peer telemetry

**Live peer telemetry** consists of kernel-observed:

- endpoint;
- latest handshake timestamp;
- received bytes;
- transmitted bytes.

It is ephemeral/observed state.

## 33. Export

An **export** serializes managed configuration into an interoperable external representation.

A standard WireGuard client configuration is an export.

Export MUST NOT imply that the exported file remains authoritative after another controller begins managing it.

## 34. Import

An **import** parses supported external WireGuard configuration into typed wg-basic desired state.

An import MUST reject or quarantine arbitrary `wg-quick` scripting semantics.

## 35. Doctor check

A **doctor check** is a bounded diagnostic producing one typed outcome and remediation guidance.

Doctor checks MUST be non-destructive unless an explicitly separate repair operation is selected.

## 36. Installation receipt

An **installation receipt** records enough package/service ownership metadata to safely update or remove files wg-basic installed.

It is distinct from host-network desired state.

## 37. Update transaction

An **update transaction** is the staged verification, candidate validation, replacement, restart/health verification, and possible rollback of wg-basic artifacts.

Eggup may provide the local transaction substrate; release authenticity remains separately owned.

## 38. State store

The **state store** is the management-service-owned SQLite database and typed access layer holding authoritative durable application state.

The state store is not available to netd and does not contain authoritative live kernel telemetry.

## 39. Desired generation

A **desired generation** is the monotonic revision of one installation's committed desired state.

Suggested type: `DesiredGeneration`.

Every successful desired-state mutation advances the generation exactly once. Callers use an expected generation to prevent stale writes from silently overwriting newer intent.

A desired generation is not a database schema version.

## 40. Committed desired state

A **committed desired state** is the complete validated application configuration stored durably at one desired generation.

Committing desired state means the operator's intent is durable. It does not by itself mean the Linux kernel has converged to that intent.

## 41. Resolved network intent

A **resolved network intent** is the deterministic privileged projection of one committed desired generation.

It contains the installation/interface ownership identity plus the typed managed-interface and firewall/forwarding policy netd needs to reconcile the kernel.

It MUST NOT contain live telemetry or arbitrary command/netlink/nftables payloads.

## 42. Owner tag

An **owner tag** is a versioned, non-secret host-visible provenance marker derived from durable installation and interface identity.

For Linux links, Phase 6 uses the interface alias (`IFLA_IFALIAS`). The nftables table uses an installation-specific ownership marker.

An owner tag is correctness/provenance evidence, not cryptographic authorization.

## 43. Convergence state

**Convergence state** is the small durable record describing the relationship between current desired generation and privileged reconciliation.

It may include:

- last attempted generation;
- last successfully converged generation;
- last attempt timestamp;
- safe high-level disposition/failure category.

Convergence state is evidence. It MUST NOT replace fresh kernel observation on startup.

## 44. State backup

A **state backup** is a consistent SQLite snapshot of the state store.

A state backup contains VPN secret material and MUST be handled with the same confidentiality expectations as the live database.

It is not a sanitized WireGuard configuration export.

## 45. Restore

A **restore** is the offline/exclusive replacement of the inactive state store from a validated backup candidate.

Restore changes durable desired state only. Normal startup reconciliation subsequently converges the kernel and still refuses foreign host ownership conflicts.

## 46. Management worker

The **management worker** is the bounded blocking execution authority owned by the unprivileged management service.

It owns `ManagementRuntime`, the SQLite-backed state store, authentication/session storage operations, and typed netd requests.

Async HTTP request tasks submit typed commands to this worker through a bounded queue. They MUST NOT access rusqlite or privileged network backends directly.

The management worker is an in-process concurrency boundary, not a network protocol.

## 47. Canonical origin

The **canonical origin** is the exact scheme, host, and optional port that browsers are expected to use for the management service.

It is the authority for:

- Host validation;
- Origin validation on unsafe methods;
- secure-cookie mode;
- HSTS eligibility.

Forwarded/X-Forwarded-* headers do not redefine the canonical origin unless a later trusted-proxy contract explicitly says so.

## 48. Session bearer token

A **session bearer token** is the high-entropy secret credential carried by the browser to identify one authenticated management session.

Suggested type: `SessionToken`.

Only a one-way digest of the bearer token is stored durably. The raw bearer token MUST NOT appear in SQLite, logs, errors, URLs, or ordinary diagnostics.

It is distinct from `SessionId`, which is a stable non-secret database identity.

## 49. CSRF token

A **CSRF token** is a session-bound secret used to prove that an authenticated unsafe browser request originated from the wg-basic application context rather than merely carrying a browser-managed session cookie.

Suggested type: `CsrfToken`.

Phase 7 uses the synchronizer-token pattern. SameSite cookies and Origin checks are additional defenses, not synonyms for the CSRF token.

## 50. Local administrator

A **local administrator** is the initially supported concrete `AdminPrincipal`: one enabled account whose password verifier is stored in the local state database.

Its password is established/reset through a local operator path, not through an unauthenticated first-browser bootstrap.

Future OIDC, TOTP, and multi-admin/RBAC work extends the principal model rather than changing this term's Phase 7 meaning.

## 51. Authentication limiter

An **authentication limiter** is the bounded in-memory admission control evaluated before expensive password verification.

It limits interactive login work using global and raw-transport-peer budgets without creating a persistent attacker-controlled account lockout.

It is application security state, not authentication truth, and is lost safely on service restart.

## 52. Advertised endpoint

An **advertised endpoint** is the application-configured host and UDP port written into generated client WireGuard configurations.

It may use a DNS name, IPv4 literal, or IPv6 literal.

It is distinct from:

- the HTTP canonical origin;
- an observed roaming peer endpoint;
- a server-side peer endpoint.

Suggested type: `AdvertisedEndpoint`.

## 53. Client label

A **client label** is bounded display metadata for a managed client.

It is never command text, hook text, a filesystem path, or executable configuration.

Suggested type: `ClientLabel`.

## 54. Enforcement state

**Enforcement state** describes whether a committed desired generation has been confirmed in the privileged/kernel layer.

Phase 8 distinguishes at least:

- `converged`;
- `pending`;
- `degraded(category)`.

A durable commit and successful enforcement are not synonyms.

This distinction is security-relevant for disable/delete: a client may be durably marked disabled while the kernel peer remains until reconciliation succeeds.

## 55. Product mutation receipt

A **product mutation receipt** is the safe result returned after a generation-CAS application mutation.

It contains:

- committed desired generation;
- stable resource identity where applicable;
- enforcement state.

It MUST NOT contain private/preshared keys unless the operation is an explicit enrollment/export artifact operation.

## 56. Audit event

An **audit event** is a durable, secret-safe record of a product/security-relevant application action.

It may record:

- event/time;
- principal or capability context;
- action category;
- stable resource identity;
- generation transition;
- bounded outcome category.

It MUST NOT contain credentials, enrollment tokens, client configurations, raw request bodies, or backend error strings.

## 57. Recently active

**Recently active** is an optional UI projection derived from live WireGuard handshake age.

It is not an authoritative connected/disconnected state and MUST NOT be persisted as desired configuration.

## 58. Status vocabulary for planning

Planning uses:

- `proposed` — direction exists but is not implementation-ready;
- `ready` — dependencies/contracts are satisfied;
- `active` — implementation in progress;
- `blocked` — named dependency prevents implementation;
- `closing` — implementation landed and closure evidence is being gathered;
- `closed` — closure evidence accepted;
- `conditionally closed` — substantial work landed but named qualification remains;
- `superseded` — replaced by a newer plan;
- `archived` — historical only.
