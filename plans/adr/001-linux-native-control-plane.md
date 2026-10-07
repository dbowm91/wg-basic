# ADR-001 — Linux-native kernel control plane with separated privilege domains

Status: accepted

Date: 2026-10-07

## 1. Context

wg-basic exists to provide wg-easy-like administration with lower canonical operational overhead and easier distribution than a Docker-first application stack.

The major architecture choices are not primarily about UI technology. They are:

1. whether wg-basic controls WireGuard through Linux kernel APIs or by generating `wg-quick`/shell configuration;
2. whether the HTTP/API service itself runs with host-network privilege;
3. whether containerization is part of the runtime architecture or only an optional distribution format;
4. how much host-network behavior is represented as typed application state versus opaque command/script hooks.

The target host is initially modern Linux with kernel WireGuard.

The application is security-sensitive because a management compromise must not automatically become arbitrary root command execution or unrestricted host-network mutation.

## 2. Forces

The selected architecture should optimize for:

- low idle memory/CPU and minimal runtime dependencies;
- installation on small x86_64/aarch64 Linux systems;
- deterministic network ownership;
- good failure/restart behavior;
- testability in Linux network namespaces;
- standard WireGuard interoperability;
- narrow privileged attack surface;
- no requirement for Docker, Node, Python, `wg-quick`, `wg`, `ip`, or iptables at runtime;
- clean future support for IPv6 and richer policy without rewriting the authority model.

## 3. Alternatives considered

### A. Docker-first application modeled closely after wg-easy

Advantages:

- familiar deployment model;
- container packages runtime dependencies;
- network capabilities can be scoped through container configuration.

Disadvantages:

- preserves the canonical overhead wg-basic is intended to remove;
- requires container runtime/network namespace/sysctl integration;
- still leaves privileged networking inside an HTTP application container;
- complicates small-host installation and host firewall interactions.

Rejected as canonical architecture. A container image may remain an optional distribution.

### B. Generate `wg-quick` configuration and invoke `wg-quick`/system tools

Advantages:

- fastest path to basic behavior;
- delegates many route/firewall behaviors;
- mirrors common manual WireGuard administration.

Disadvantages:

- arbitrary hook directives make configuration text a command surface;
- mixes WireGuard identity with route/firewall/shell semantics;
- host mutation becomes difficult to model, diff, and prove;
- runtime depends on several external tools;
- rollback/reconciliation is command-oriented rather than state-oriented;
- unsafe fit for fields originating in a web/API control plane.

Rejected as the internal control architecture.

### C. One privileged monolithic Rust HTTP/server process

Advantages:

- simplest process topology;
- one service unit;
- no IPC protocol.

Disadvantages:

- HTTP parsing, authentication, UI/API routing, database code, and future third-party dependencies share `CAP_NET_ADMIN`/root authority;
- any application compromise has unnecessary host-network privilege;
- difficult to establish a small auditable privileged core.

Rejected.

### D. Linux-native typed kernel control plus privilege-separated process roles

Architecture:

```text
unprivileged management service
          |
          | typed UDS IPC
          v
privileged network service
          |
          +--> WireGuard Generic Netlink
          +--> RTNETLINK
          +--> nftables/netfilter
          `--> bounded forwarding/sysctl behavior
```

Advantages:

- low runtime overhead;
- no container/language runtime requirement;
- narrow privileged API;
- deterministic typed reconciliation;
- strong Linux namespace testability;
- clean separation of desired and observed state;
- application can still ship as one executable.

Disadvantages:

- requires a versioned local IPC protocol;
- direct kernel/network semantics require more implementation and testing than shelling out;
- nftables and host forwarding ownership need careful design;
- Linux-first product boundary is explicit.

Selected.

## 4. Decision

wg-basic will use Alternative D.

The canonical product is a Linux-native Rust executable with at least two separable runtime roles:

- management service: unprivileged, owns persistence/authentication/API/UI/orchestration;
- network service: privileged, owns bounded host-network observation and mutation.

The Linux kernel WireGuard implementation is the canonical VPN dataplane.

The network service uses typed native control APIs. Runtime shell command generation is not the network-control architecture.

Containerization is optional packaging only.

## 5. Privileged protocol constraints

The management-to-network protocol MUST be local, authenticated through filesystem/socket ownership and available peer credentials, versioned, and typed.

It MUST NOT offer generic:

- shell execution;
- process spawning;
- arbitrary file write;
- arbitrary sysctl mutation by path;
- raw caller-supplied nftables script;
- raw netlink forwarding.

The privileged service revalidates operation scope/ownership itself.

A management-process compromise therefore grants, at worst, the explicitly designed wg-basic privileged operations rather than arbitrary root execution.

## 6. Host networking decision

WireGuard, link, address, route, forwarding, firewall, and NAT concepts remain separate typed domains.

The reconciliation model is:

```text
desired state
 -> observe
 -> validate ownership/conflicts
 -> derive typed mutations
 -> apply in defined order
 -> re-observe
 -> verify
```

The first nftables implementation MAY invoke the host `nft` binary only if the owning milestone demonstrates that doing so is materially safer/smaller than a native backend and the privileged protocol still accepts typed policy rather than raw nft source from the management process.

The architectural target remains direct kernel/netfilter control. Any external-command transition path must be internal to the privileged service, bounded, non-shell, and explicitly retired or justified by a later ADR.

## 7. State decision

Durable desired state belongs to the management/service state store.

Kernel state is observed state.

Generated WireGuard configuration files are exports, not authoritative state.

The privileged network service SHOULD remain as stateless as practical beyond runtime locks/caches; durable ownership facts required for safe mutation must be reconstructable from the versioned desired state and bounded installation metadata.

## 8. Eggstack consequences

This decision permits selective Eggstack reuse without placing Eggstack inside the kernel authority boundary unnecessarily.

- EggServe is compatible with the unprivileged HTTP service.
- Eggup and Eggpack are compatible with distribution/update phases.
- No Eggstack crate is selected as the WireGuard/RTNETLINK/nftables authority unless a later implementation plan demonstrates a direct contract match.

## 9. Security consequences

Positive:

- public HTTP parsing does not require network-admin capability;
- arbitrary shell hook injection is removed from the domain;
- privileged operations can be exhaustively enumerated and fuzzed/tested;
- network mutation has one auditable authority;
- systemd can sandbox the two roles differently.

Costs:

- local IPC is now a security boundary and must be versioned/tested;
- peer-credential and socket-permission behavior must be qualified on supported Linux distributions;
- secret transfer across IPC must be minimized and redacted.

## 10. Compatibility consequences

Standard WireGuard peers/configuration remain interoperable.

wg-basic will not promise arbitrary `wg-quick` script compatibility.

If a future import capability reads `wg-quick` files, only explicitly supported declarative fields may become wg-basic state. Hook directives remain rejected or inert data.

## 11. Migration consequences

There is no prior wg-basic production architecture to migrate.

A future decision to support non-Linux platforms should introduce backend-specific implementations behind the typed authority boundaries rather than replacing the domain model.

A future decision to merge privilege domains requires a superseding ADR and a new threat-model review.

## 12. Verification consequences

Milestones claiming kernel behavior require Linux integration evidence.

The privileged boundary requires tests for:

- authorized local caller;
- unauthorized caller;
- malformed/unknown protocol version;
- oversized/bounded request behavior;
- management-process inability to request generic execution;
- restart/disconnect handling;
- cancellation/timeouts without orphaned mutation tasks.

Kernel mutation milestones require network namespace fixtures and preservation checks for unrelated state.

## 13. References considered

Implementation research should continue to consult:

- Linux WireGuard Generic Netlink/UAPI;
- rtnetlink/netlink-packet-wireguard ecosystem;
- DefGuard `wireguard-rs` and `wireguard-control` as Rust control-layer prior art;
- nftables/netfilter Rust libraries and the `nft` CLI only as bounded backend options;
- wg-easy as the principal UX reference;
- nx9-wg and similar Rust/Linux appliances as architectural prior art, not source templates;
- EggServe/Eggup/Eggpack public contracts for the specific downstream roles described above.

Licensing and current API maturity MUST be rechecked in the implementation milestone before adding a dependency.
