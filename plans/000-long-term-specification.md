# wg-basic Long-Term Architecture and Product Specification

Status: canonical long-term implementation directive

Companion documents:

- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`

This document defines the intended end state for wg-basic. It establishes product scope, ownership boundaries, security properties, host-network behavior, interoperability requirements, operational expectations, and completion criteria. The roadmap decomposes this specification into ordered work. The terminology document is normative when implementation or documentation uses overlapping networking terms.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative.

## 1. Product definition

wg-basic is a Linux-native WireGuard administration appliance focused on the same low-friction outcome that makes wg-easy useful: install it, open a small management surface, create a client, scan a QR code or download a standard WireGuard configuration, and have a working VPN.

Its canonical deployment is not a container. The normal installation is one signed/prebuilt Rust executable plus small host service/configuration files. The Linux kernel owns the WireGuard dataplane. wg-basic owns only the control plane required to configure that dataplane and the minimum host networking needed for the appliance.

The product is intentionally narrower than a general network controller. It exists to make ordinary WireGuard server administration easy, low-overhead, auditable, and easy to distribute to small Linux hosts including ARM SBCs.

## 2. Primary product goals

wg-basic MUST provide:

1. A canonical non-container installation with no mandatory Node, Python, Docker, Podman, `wg-quick`, `wg`, `ip`, or iptables runtime dependency.
2. A small Rust control plane over the Linux kernel WireGuard implementation.
3. First-run setup that produces a functional server without requiring the operator to understand netlink, nftables, policy routing, or WireGuard configuration syntax.
4. Simple client lifecycle: create, inspect, disable/revoke, delete, export configuration, and render QR enrollment.
5. Correct live telemetry for latest handshake, roaming endpoint, received bytes, and transmitted bytes.
6. Typed, deterministic ownership of interface, address, route, forwarding, and application-owned firewall/NAT state.
7. Durable desired state that can reconstruct managed kernel state after restart.
8. Strong separation between Internet-facing management code and privileged host-network mutation.
9. Standard WireGuard configuration export and an escape hatch for operators who later choose another controller.
10. Low idle resource use suitable for Raspberry Pi and comparable SBC/server installations.
11. Straightforward installation, update, rollback, backup, diagnostics, and uninstall behavior.
12. IPv4 as an initial supported path and IPv6 as a required long-term capability rather than an architectural afterthought.

## 3. Non-goals

wg-basic is not initially:

- a WireGuard dataplane implementation;
- a userspace replacement for Linux kernel WireGuard;
- a Kubernetes/network-overlay controller;
- a general host firewall editor;
- a general router or SDN control plane;
- a multi-host mesh coordination service;
- a commercial identity/zero-trust platform;
- an arbitrary shell-hook runner;
- a replacement for NetworkManager or systemd-networkd;
- a general-purpose VPN client manager for third-party upstream providers;
- an HA/multi-primary control plane;
- a requirement to match every wg-easy feature before the first useful release.

OIDC, TOTP, multi-admin RBAC, AmneziaWG, third-party upstream VPN import, policy-rich per-client firewalls, and multi-server coordination MAY be added later only if they preserve the product's simplicity and privilege boundaries.

## 4. Architectural principles

### 4.1 Kernel dataplane, Rust control plane

The Linux kernel MUST remain the canonical WireGuard dataplane on supported hosts. wg-basic MUST configure it through typed kernel interfaces rather than reimplementing packet encryption or forwarding in userspace.

### 4.2 No arbitrary command generation

Normal runtime behavior MUST NOT construct shell commands or `wg-quick` hook text from API/UI fields. There is no general `PreUp`, `PostUp`, `PreDown`, or `PostDown` field in the canonical model.

External programs MAY be used by development/qualification tooling, installers, or operator diagnostics when explicitly documented. Production network mutation SHOULD converge toward direct kernel APIs.

### 4.3 One distributable executable does not imply one privilege domain

wg-basic SHOULD ship one executable containing multiple process roles. The privileged network-control role and the unprivileged management role MUST be separable at runtime.

The network-control role MUST expose a narrow typed local IPC surface. It MUST NOT expose a public HTTP listener or accept arbitrary command strings, filesystem paths, nftables programs, or shell fragments from the management process.

### 4.4 Desired state is authoritative; kernel state is observed state

Durable application state defines what wg-basic intends to own. Kernel state is observed and reconciled against that intent.

A generated `wg0.conf` is an export artifact, not the authoritative database.

### 4.5 Explicit host ownership

wg-basic MUST own only resources it can identify as its own. Firewall state MUST live in a dedicated application namespace/table. Routes, links, and addresses MUST be tagged or structurally attributable where the kernel API permits.

The application MUST NOT flush, replace, or opportunistically repair unrelated host firewall, route, interface, or sysctl state.

### 4.6 Fail closed on uncertain destructive/network mutation

If wg-basic cannot prove that a mutation is within its ownership boundary, it MUST refuse the mutation and surface an actionable diagnostic rather than guessing.

### 4.7 Easy defaults, inspectable behavior

The default road-warrior setup SHOULD require minimal input: server endpoint, tunnel subnet, listen port, and optional DNS preference. Advanced decisions remain visible and exportable.

The product MUST provide a dry-run/plan representation for host-network reconciliation before dangerous or broad changes.

### 4.8 Small dependency and runtime surface

Dependencies MUST justify their runtime or maintenance cost. Eggstack components MAY be adopted when their contract directly replaces project-local machinery; family membership alone is not a reason to depend on a crate.

## 5. Canonical deployment model

The target Linux deployment is:

```text
Browser / CLI
      |
      v
wg-basic management service
  unprivileged service account
  HTTP/API + embedded UI
  SQLite desired state + secrets
      |
      | authenticated Unix-domain IPC
      v
wg-basic network service
  CAP_NET_ADMIN or narrowly required root privilege
      |
      +--> WireGuard Generic Netlink
      +--> RTNETLINK
      +--> NETLINK_NETFILTER / nftables
      `--> narrowly scoped forwarding/sysctl ownership
               |
               v
           Linux kernel
```

The same executable MAY expose process roles such as:

```text
wg-basic serve
wg-basic netd
wg-basic doctor
wg-basic status
wg-basic config ...
wg-basic update
```

Exact command names are implementation details until the CLI contract is closed, but runtime roles MUST preserve the ownership split.

## 6. Platform scope

### 6.1 Initial support

Initial production support targets modern Linux distributions with kernel WireGuard support.

Tier-1 architecture targets:

- Linux x86_64;
- Linux aarch64.

ARMv7 MAY be added where dependency/toolchain support and release qualification are practical.

### 6.2 Deferred platforms

macOS, Windows, FreeBSD, and userspace-WireGuard hosts are deferred. Internal domain APIs SHOULD avoid gratuitous Linux assumptions where doing so is cheap, but cross-platform abstraction MUST NOT complicate the first Linux implementation.

## 7. WireGuard domain requirements

A managed WireGuard interface MUST model at least:

- stable application identifier;
- kernel interface name;
- private/public key identity;
- optional listen port;
- tunnel IPv4/IPv6 addresses;
- MTU policy;
- enabled/disabled lifecycle;
- server endpoint advertised to clients;
- peer set.

A peer/client MUST model at least:

- stable identifier;
- human label;
- public key;
- encrypted/otherwise protected private key material when wg-basic generated the client identity;
- optional preshared key;
- assigned tunnel addresses;
- server-side cryptokey-routing AllowedIPs;
- client-side route policy;
- optional DNS servers;
- optional persistent keepalive;
- enabled/revoked state;
- creation/update timestamps.

Server-side peer AllowedIPs and client-side route policy MUST remain distinct concepts. A road-warrior client assigned `10.8.0.2/32` SHOULD normally appear to the server as `10.8.0.2/32` while its generated client configuration may contain `0.0.0.0/0` for a full-tunnel profile.

Duplicate key, address, and overlapping server-side cryptokey-route conflicts MUST be rejected before kernel mutation.

## 8. Key and secret handling

Private keys, preshared keys, password verifiers, session secrets, and one-time enrollment capabilities are secrets.

wg-basic MUST:

- generate WireGuard private keys using a cryptographically secure source;
- never log private key or preshared-key material;
- redact secrets from `Debug` and structured diagnostics;
- use restrictive filesystem permissions for durable secrets;
- avoid placing secrets in process arguments;
- make QR/config export an authenticated operation;
- clearly label exported client configuration as secret material;
- use high-entropy, expiring, single-use capability tokens for any one-time configuration URL;
- store one-time tokens in a non-recoverable verifier form when practical.

Secrets MUST NOT be passed through arbitrary text command execution.

## 9. Host networking ownership

wg-basic MUST distinguish:

1. WireGuard device configuration;
2. link lifecycle;
3. interface addresses;
4. routes required for managed tunnel subnets;
5. packet forwarding state;
6. firewall/filter rules;
7. NAT/masquerade rules.

Those layers may share a reconciliation transaction but MUST remain separate typed operations.

wg-basic MUST NOT replace the host default route as part of ordinary server setup.

The application SHOULD own one nftables table, for example `inet wg_basic`, and MUST NOT flush or mutate unrelated tables.

The initial NAT policy SHOULD be simple masquerade from the managed tunnel subnet to selected/non-WireGuard egress. Per-client arbitrary firewall scripting is deferred.

## 10. Forwarding/sysctl semantics

Enabling server forwarding is a host mutation and MUST be explicit in the desired network plan.

Implementation MUST record whether forwarding was already enabled and MUST avoid blindly disabling host-wide forwarding during teardown when wg-basic did not establish exclusive ownership.

If safe ownership cannot be represented for a host-wide sysctl, uninstall/disable behavior SHOULD preserve the enabled value and report it rather than risk breaking another service.

## 11. Reconciliation model

Every network change SHOULD be represented as:

```text
desired state
    |
    v
observe kernel state
    |
    v
derive typed plan
    |
    +--> validate ownership/conflicts
    |
    +--> dry-run representation
    |
    v
apply ordered mutations
    |
    v
re-observe and verify
```

Reconciliation MUST be serialized per managed interface/firewall namespace.

Operations SHOULD be idempotent. A successful repeat against already-converged state SHOULD produce no mutation.

A partial failure MUST produce enough typed evidence to retry safely. Rollback is REQUIRED where the previous owned state can be restored without risking unrelated state; otherwise the system MUST stop and report the exact incomplete state.

## 12. Durable storage

SQLite is the preferred authoritative store unless implementation evidence demonstrates a materially better option.

Storage MUST separate durable desired state from live telemetry.

Expected durable domains include:

- schema/version metadata;
- interface configuration;
- peers;
- address assignments;
- client route/DNS policy;
- server endpoint settings;
- firewall/NAT policy;
- administrator/authentication state;
- sessions/tokens;
- audit events;
- migration metadata.

Live handshake times, roaming endpoints, and byte counters SHOULD be read from the kernel and MUST NOT become stale authoritative configuration.

Database migrations MUST be ordered, transactional where possible, and covered by upgrade/rollback-oriented tests.

## 13. Privileged IPC boundary

The privileged network service MUST authenticate its local caller through Unix socket ownership/permissions and, where available, peer credentials.

The IPC protocol MUST be versioned and typed.

Allowed privileged operations SHOULD resemble:

```text
InspectCapabilities
ObserveManagedState
PlanReconcile
ApplyReconcile
GetLivePeerTelemetry
```

or narrower typed interface/peer/network operations.

The protocol MUST NOT expose:

- execute-command;
- arbitrary shell;
- arbitrary file write;
- arbitrary sysctl path;
- arbitrary netlink payload;
- raw nftables program supplied by the HTTP client.

The network service owns validation again at the privilege boundary; it MUST NOT assume that validation in the management process is sufficient.

## 14. Management HTTP/API/UI

The management surface SHOULD remain small and appliance-oriented.

The first useful UI needs:

- first-run setup;
- login/session management;
- server status;
- peer list;
- peer create/edit/disable/delete;
- client config export;
- QR enrollment;
- latest handshake and transfer counters;
- concise diagnostics.

A large SPA framework is not required. Static assets SHOULD be embedded into the binary.

The HTTP server MUST default to a conservative bind policy. Public/LAN exposure must be explicit and documented.

CSRF/session protection, request-size limits, rate limiting for authentication/token endpoints, security headers, and secret-safe errors are REQUIRED before public release.

## 15. Eggstack reuse policy

### 15.1 EggServe

`eggserve-server` / `eggserve-primitives` are the preferred first candidate for the Rust HTTP transport because EggServe already owns hardened parsing, framing, limits, timeouts, connection lifecycle, Unix listeners, and optional Tower interoperability.

wg-basic still owns application routing, authentication, API semantics, and UI assets. If EggServe creates materially more complexity than a conventional framework for the small API, the implementation milestone MUST record the comparison rather than force adoption.

### 15.2 Eggup

Eggup is the preferred substrate for later self-update/install replacement mechanics:

- staged candidate installation;
- SHA-256 integrity verification;
- destination ownership revalidation;
- locking;
- replacement;
- rollback/recovery evidence;
- service lifecycle integration through `eggup-service`.

Authenticity/signature verification remains a wg-basic/release-policy responsibility because Eggup explicitly claims integrity, not publisher authenticity.

### 15.3 Eggpack

Eggpack is the preferred producer-side release contract once wg-basic has a stable binary and target matrix. It SHOULD generate/qualify deterministic release artifacts and draft release state while leaving final publication human-controlled.

### 15.4 Explicit non-adoptions

wg-basic SHOULD NOT depend on Eggfetch, Eggress, Eggprobe, Eggsact, Eggsearch, or other Eggstack crates unless a concrete wg-basic requirement appears that they own better than a small local implementation.

In particular, Eggprobe's current native contract does not provide authoritative WireGuard or nftables control, and no HTTP client is required in the ordinary VPN control plane.

## 16. Installation and operations

The intended operator flow is approximately:

```text
install release binary
    -> wg-basic install / installer bootstrap
    -> host capability preflight
    -> create system user/directories
    -> install service units
    -> initialize admin
    -> start services
    -> print management URL + next action
```

Canonical persistent locations SHOULD follow ordinary Linux conventions:

- `/etc/wg-basic/` for operator configuration;
- `/var/lib/wg-basic/` for durable application state;
- a runtime directory under `/run/` for IPC sockets.

Exact paths remain configurable.

A `doctor` command MUST provide actionable, secret-safe checks for kernel WireGuard availability, privilege/capability state, interface/port conflicts, forwarding, nftables support, service health, storage permissions, and owned-state drift.

Uninstall MUST distinguish binary/service removal from destructive purge of VPN state.

## 17. Distribution and update requirements

The first public release SHOULD provide at least x86_64 and aarch64 Linux artifacts.

Release artifacts MUST have:

- explicit source/version identity;
- checksums;
- an authenticity mechanism or trusted release-channel policy;
- reproducible/documented build inputs where practical;
- rollback-safe update behavior.

Container images MAY be published as an optional compatibility distribution, but Docker/Podman MUST NOT be required by the architecture.

## 18. Import/export and interoperability

wg-basic MUST export ordinary WireGuard client configuration compatible with standard clients.

A future import path MAY support a constrained subset of `wg-quick` configuration, but arbitrary hook directives MUST never become executable application state.

Import must distinguish recognized WireGuard fields from ignored/rejected `wg-quick` host scripting.

## 19. Observability

Normal logs MUST be structured enough to answer:

- which managed resource changed;
- why reconciliation ran;
- whether a change was planned/applied/verified;
- which peer identifier was affected;
- whether failure occurred before or after kernel mutation.

Logs MUST NOT contain secret material.

Prometheus/OpenMetrics output MAY be added after core correctness. Peer labels exposed as metrics MUST avoid unbounded/high-cardinality surprises.

## 20. Security model

The principal threats include:

- compromise of the management HTTP service;
- command/config injection;
- theft of client/server private keys;
- CSRF/session theft;
- malicious or accidental route/firewall changes;
- confused ownership with Docker/firewalld/other nftables users;
- unsafe upgrade/recovery;
- privilege escalation through the local network-control protocol.

Security requirements therefore include:

- no arbitrary root command surface;
- privilege separation before Internet/LAN-facing release;
- strict input validation and typed kernel operations;
- dedicated firewall ownership namespace;
- restrictive filesystem/socket permissions;
- memory-safe Rust by default and narrowly reviewed `unsafe` only where unavoidable;
- dependency/supply-chain review appropriate to privileged software;
- explicit resource/request bounds in the management service;
- integration tests that prove unrelated host rules/routes are preserved.

## 21. Test and qualification strategy

The core networking implementation MUST be testable in disposable Linux network namespaces.

Tests SHOULD create isolated namespaces/veth pairs and verify:

- interface creation/removal;
- key/listen-port configuration;
- peer add/update/remove;
- address assignment;
- route creation/removal;
- nftables rule ownership;
- NAT/forwarding behavior;
- idempotent reconciliation;
- partial failure/retry;
- preservation of unrelated links/routes/firewall tables;
- restart reconstruction from durable desired state.

Unit tests and mocked netlink alone are insufficient for network-control closure.

Release qualification SHOULD include at least one real kernel WireGuard handshake between isolated peers and one representative ARM64 build/run path before claiming SBC support.

## 22. Performance and footprint objectives

wg-basic does not claim dataplane throughput improvements over kernel WireGuard.

Performance work targets the control plane:

- idle CPU should be effectively negligible;
- control-plane memory should remain small enough for constrained SBC use;
- startup and ordinary peer operations should feel immediate;
- there should be no resident container runtime or language runtime requirement.

Initial engineering targets, to be measured rather than assumed, are:

- total steady-state application RSS below 30 MiB for a small installation;
- cold service readiness below 500 ms on a representative modern x86_64 host;
- no periodic reconciliation loop that wakes aggressively when state is converged.

Failure to meet a target is not permission to weaken correctness or privilege separation.

## 23. Prior-art boundary

wg-easy remains the primary user-experience reference: low-friction self-hosted WireGuard administration.

Other Rust/Linux WireGuard control planes, including nx9-wg and DefGuard components, are useful architecture and interoperability references. wg-basic MUST NOT become a source clone of those projects. Its differentiation is narrower appliance scope, wg-easy-like onboarding, explicit privilege separation, small canonical deployment, and Eggstack-based distribution/operations where those primitives fit.

## 24. Long-term completion definition

The product reaches its intended baseline when:

1. a supported Linux host can install wg-basic without Docker or a language runtime;
2. first-run setup can create a usable WireGuard server;
3. a user can add a peer, scan/export configuration, connect, and see live handshake/traffic state;
4. kernel WireGuard, address, route, forwarding, and firewall ownership is deterministic and restart-safe;
5. management and privileged network mutation run in separate privilege domains;
6. unrelated host network/firewall state survives installation, reconciliation, disable, update, and uninstall;
7. durable state can be backed up, migrated, and restored;
8. updates are verified, rollback-safe, and operationally simple;
9. x86_64 and aarch64 release artifacts are qualified;
10. security and integration tests demonstrate the principal privilege/network ownership invariants.
