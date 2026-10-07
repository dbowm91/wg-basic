# Network Control M002 — Privileged Protocol and Host Capability Boundary

Status: ready

Repository planning baseline: `e27034ef404912e6f8206588ddcf7be59d5c48da` (M001 implementation)

Source roadmap:

- `plans/subsystems/network-control-roadmap.md#8-milestone-m002--privileged-protocol-and-host-capability-boundary`
- `plans/002-long-term-roadmap.md#4-phase-2--privileged-protocol-and-host-capability-boundary`

Canonical requirements:

- `plans/000-long-term-specification.md#13-privileged-ipc-boundary`
- `plans/001-terminology-and-domain-model.md#22-privileged-protocol`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: invariant / infrastructure

Hard dependency:

- M001 strictly closed.

## 1. Objective

Make the management/network privilege split executable before broad kernel mutation is introduced.

M002 creates:

- one executable with distinct `serve` and `netd` runtime roles;
- a bounded, versioned Unix-domain IPC contract;
- caller authentication/authorization appropriate to a local privileged service;
- read-only host-capability/preflight observation;
- shutdown/cancellation semantics;
- the protocol extension pattern M003–M005 will use for typed privileged operations.

M002 MUST NOT implement WireGuard, route, address, firewall, NAT, or forwarding mutation.

## 2. Entry review

Before coding:

1. inspect M001 closure and final module/crate shape;
2. reuse M001 domain/error types instead of creating protocol-specific duplicates;
3. verify current Linux/MSRV dependencies for UDS peer credentials and filesystem ownership;
4. confirm no newly added M001 dependency already owns a suitable bounded framing layer;
5. record the implementation baseline commit in this plan/closure handoff if it differs materially from the planning baseline.

If M001 changed the runtime-role or domain boundary, revise this ready handoff before implementation rather than layering an incompatible protocol on top.

## 3. IPC transport

Canonical transport is a Unix-domain stream socket under an installation-owned runtime directory such as:

```text
/run/wg-basic/netd.sock
```

Exact runtime path/configuration belongs to implementation/config policy.

Requirements:

- parent runtime directory not world-writable;
- socket owner/group/mode explicit;
- stale socket handling safe and ownership-aware;
- no TCP fallback;
- no automatic public bind;
- listener cleanup does not unlink an unexpected non-owned path.

Systemd socket activation MAY be supported later. Do not require it in M002 unless it materially simplifies safe ownership.

## 4. Caller authorization

The network service MUST authorize the local caller independently of message contents.

Use the strongest practical Linux-local identity available without requiring a heavyweight external daemon.

Expected inputs:

- Unix socket filesystem permissions;
- `SO_PEERCRED` or equivalent peer UID/GID/PID evidence.

Initial policy may authorize:

- the dedicated wg-basic management-service UID;
- root/operator fixture identity where required for controlled administration/tests.

Do not trust a caller-supplied UID/PID field.

The authorization policy MUST be explicit and unit/integration testable.

## 5. Protocol framing

Use a bounded binary-safe frame.

A reasonable shape is:

```text
u32_be length
payload bytes
```

with a small protocol maximum appropriate to control messages.

The payload encoding may be JSON, MessagePack/postcard, or another mature Serde-compatible format. Select based on:

- MSRV;
- maintenance;
- unknown-field/version behavior;
- bounded decoding;
- diagnostics;
- dependency footprint.

The security property comes from typed validation + framing + authorization, not from using a binary format.

Do not use unbounded newline reads or deserialize directly from an unbounded stream.

## 6. Versioned envelope

Define explicit protocol identity.

Conceptually:

```text
RequestEnvelope {
    protocol_version,
    request_id,
    operation,
}

ResponseEnvelope {
    protocol_version,
    request_id,
    result,
}
```

Requirements:

- unknown major version rejected;
- request/response correlation;
- bounded operation payload;
- stable error category;
- no reflection of arbitrary malformed bytes in logs/errors;
- future additive operations possible without renumbering unrelated domain IDs.

Do not expose Rust enum discriminants as an undocumented wire contract if the chosen serializer makes them unstable.

## 7. Initial operation surface

M002 should intentionally keep the privileged operation set tiny.

Required operations:

### Ping / protocol info

Returns bounded service/protocol/version identity without secrets.

### InspectCapabilities

Returns a typed `NetworkCapabilitySnapshot`.

Candidate facts:

- OS = Linux;
- architecture;
- effective UID/GID;
- whether required runtime paths/socket are safe;
- whether process appears to hold `CAP_NET_ADMIN`;
- kernel release for diagnostics;
- whether network namespaces appear usable in the current environment;
- WireGuard-control support state where it can be established read-only without prejudging M003 backend selection;
- nftables/netfilter support state where it can be established read-only without mutation.

Capability fields MUST permit `unknown` / `not probed` where authoritative probing belongs to a later backend. Do not infer false support from kernel version alone.

### ObserveServiceState

Optional if useful: exposes only netd-owned runtime status, not kernel WireGuard state.

No mutation operation is required in M002.

## 8. Forbidden protocol shapes

M002 MUST add tests/source review preventing operations equivalent to:

- `Exec { command: String }`;
- `Shell { script: String }`;
- `WriteFile { path, bytes }`;
- `SetSysctl { path: String, value: String }`;
- `ApplyNft { source: String }`;
- `SendNetlink { bytes }`.

Later operations must encode wg-basic domain intent, not generic privileged mechanisms.

## 9. Connection/task bounds

The network service is local but still must treat IPC input as adversarial.

Define bounded:

- maximum frame size;
- maximum simultaneous connections;
- per-connection in-flight requests, preferably one initially;
- read/write/idle timeout or cancellation behavior;
- total decoded collection sizes;
- error response size.

Avoid unbounded task spawning and queues.

A small fixed/bounded model is appropriate because control-plane throughput requirements are low.

## 10. Shutdown and cancellation

The network service MUST:

- stop accepting on shutdown;
- cancel/close idle readers;
- finish or cancel read-only requests promptly;
- leave no detached tasks;
- remove its socket only when it still owns the expected socket path;
- return a clear process exit status.

M002 has no mutation transaction to recover.

The protocol design MUST leave room for later mutation cancellation semantics without assuming mutation can always be rolled back.

## 11. Capability observation

Read-only probes must not mutate the host merely to determine capability.

Avoid:

- creating interfaces;
- changing sysctls;
- loading kernel modules;
- installing nftables objects.

It is acceptable for a capability to remain “unknown until M003/M005 backend initializes.”

A later `doctor --fix` would be a separate mutating contract; M002 `doctor` is read-only.

## 12. Systemd privilege contract

Add current-behavior/operator documentation describing how `netd` is expected to run once installed.

Do not ship an over-hardened service file that prevents future netlink work without tests.

Document the intended direction:

- dedicated service user where practical;
- `CAP_NET_ADMIN` only for network service;
- management service without `CAP_NET_ADMIN`;
- filesystem access restricted to runtime/config/state needed by each role;
- no shell requirement.

Actual service units may remain later distribution work unless a fixture unit is useful for M002 qualification.

## 13. Test strategy

### Protocol unit tests

Cover:

- round-trip every M002 request/response;
- max-frame boundary;
- oversized frame rejection before allocation;
- truncated frame;
- unknown protocol version;
- unknown operation;
- malformed payload;
- duplicate/incorrect request correlation where relevant;
- secret-free error formatting.

### Authorization integration

On Linux:

- socket created with intended ownership/mode;
- authorized caller succeeds;
- deliberately unauthorized caller is denied where the test environment permits creating distinct credentials;
- peer credential comes from kernel, not payload;
- stale/unexpected socket-path object is not blindly deleted.

If hosted CI cannot create a distinct UID, use a focused rootful integration fixture in a qualifying environment and keep ordinary CI unit coverage. Do not fake strict closure.

### Lifecycle tests

- connect/disconnect repeatedly;
- client drops mid-frame;
- server shutdown with idle client;
- bounded connection saturation;
- socket cleanup/restart.

## 14. Verification

Routine:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Linux IPC integration:

```text
cargo test --locked --test privileged_protocol -- --nocapture
```

Exact test target name is implementation-defined.

Add a focused search/guard showing no production privileged generic-exec operation was introduced.

## 15. Documentation

Update:

- `architecture/overview.md`;
- add `architecture/privilege-boundary.md`;
- developer docs for running `netd` in an unprivileged read-only M002 mode;
- CLI docs for `doctor` if exposed;
- registry/subsystem status only after closure evidence.

Current docs MUST state that WireGuard mutation is still not implemented.

## 16. Acceptance criteria

M002 closes only when:

1. `serve` and `netd` are distinct executable roles;
2. netd accepts only local UDS connections;
3. frames and concurrency are bounded;
4. protocol versioning and request correlation are explicit;
5. kernel-derived peer identity participates in authorization;
6. authorized capability inspection works;
7. unauthorized/malformed callers fail safely;
8. capability inspection performs no host-network mutation;
9. no generic privileged escape hatch exists;
10. shutdown/restart leaves no stale owned socket problem;
11. MSRV and routine verification pass;
12. docs describe the implemented privilege boundary truthfully.

## 17. Stop conditions

Stop and report if:

- correct peer-credential authorization would require weakening portability assumptions beyond Linux;
- the chosen serialization/framing dependency raises MSRV or footprint disproportionately;
- implementation requires network mutation just to establish M002 capability facts;
- management and network roles cannot remain separate without moving durable state into netd;
- a proposed convenience requires generic command execution.

## 18. Closure evidence

Record:

- final protocol schema/encoding and max frame size;
- socket ownership/mode;
- authorization policy;
- dependency additions and rationale;
- exact protocol/lifecycle test results;
- unauthorized-caller evidence;
- capability snapshot example with no secrets;
- source guard results;
- hosted CI;
- known environment-specific gaps.

M003 becomes `ready` only after M002 strict closure.
