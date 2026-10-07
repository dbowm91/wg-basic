# Network Control M003 — WireGuard Kernel Control and Live Telemetry

Status: closed

Repository planning baseline: `f888e359e4828f3499a4fb6dbe1fe251fd20bdce` (M002 strict implementation)

Source roadmap:

- `plans/subsystems/network-control-roadmap.md#9-milestone-m003--wireguard-kernel-control-and-live-telemetry`
- `plans/002-long-term-roadmap.md#5-phase-3--direct-wireguard-control-and-live-telemetry`

Canonical requirements:

- `plans/000-long-term-specification.md#7-wireguard-domain-requirements`
- `plans/000-long-term-specification.md#8-key-and-secret-handling`
- `plans/001-terminology-and-domain-model.md`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: capability / invariant

Hard dependency:

- M002 strictly closed.

## 1. Objective

Implement authoritative Linux kernel WireGuard configuration and observation through a typed Rust backend and expose only the required operations through the M002 privileged protocol.

M003 proves that wg-basic can manage WireGuard devices/peers and read live telemetry without runtime invocation of `wg` or `wg-quick`.

M003 intentionally does not own production RTNETLINK address/route lifecycle or firewall/NAT behavior.

## 2. Required dependency/backend research

Before implementation, compare the current maintained Rust options rather than selecting from stale planning assumptions.

At minimum evaluate:

1. a maintained high-level WireGuard-control crate such as DefGuard's WireGuard Rust control layer;
2. `wireguard-control`/innernet-family control primitives if still maintained and suitable;
3. lower-level Generic Netlink composition using `netlink-packet-wireguard` plus the current generic-netlink socket stack;
4. newer consolidated netlink libraries such as `nlink` if their API/maturity now justifies adoption.

Record for each serious candidate:

- license;
- latest release/current maintenance evidence;
- MSRV;
- Linux kernel WireGuard support;
- device get/set support;
- peer add/update/remove/replace behavior;
- AllowedIPs;
- persistent keepalive;
- endpoint;
- handshake/RX/TX observation;
- interface creation assumptions;
- async/blocking behavior;
- dependency footprint;
- use of unsafe/FFI;
- ability to preserve unknown/unowned peer state;
- error fidelity;
- testability.

Selection rule:

Prefer a mature high-level crate if it exposes the required Linux semantics without forcing userspace-WireGuard or cross-platform runtime baggage. Fall back to lower-level Generic Netlink only when the high-level abstraction prevents correct ownership/reconciliation.

Do not fork/copy another project's implementation merely to avoid a dependency.

If no candidate can safely support the required peer mutation semantics, stop and write a dependency/backend ADR or corrective research plan.

## 3. Production backend contract

Introduce one Linux WireGuard backend authority.

Conceptually:

```text
trait WireGuardBackend {
    observe_device(locator) -> ObservedWireGuardDevice
    apply_device_config(locator, DevicePatch) -> ApplyReceipt
}
```

Exact trait shape is implementation-defined.

The contract MUST support:

- querying device public/listen identity;
- querying all peers;
- setting server private key/listen port where requested;
- adding a peer;
- updating a peer;
- removing a peer;
- replacing AllowedIPs intentionally without accidentally replacing unrelated peer fields;
- optional peer endpoint configuration if wg-basic needs it;
- persistent keepalive;
- live endpoint/latest-handshake/RX/TX.

Avoid a “send arbitrary netlink attributes” escape hatch above the backend.

## 4. Device lifecycle boundary

M003 does not own general link creation/deletion; M004 owns link lifecycle through RTNETLINK.

For integration fixtures, a WireGuard link MAY be created and removed by test harness setup using host tooling such as `ip link add ... type wireguard`, because that is fixture plumbing rather than shipped runtime behavior.

Production M003 code should configure an existing WireGuard link and return a typed “missing/wrong link” outcome.

If the selected WireGuard crate itself necessarily creates devices and doing so cleanly improves the architecture, stop and reconcile M003/M004 ownership before expanding scope.

## 5. Key representation and generation

M003 is the first milestone that must make WireGuard key semantics concrete.

Requirements:

- 32-byte WireGuard private/public key representation;
- cryptographically secure private-key generation;
- correct WireGuard/X25519 private-key clamping/derivation semantics;
- standard base64 export/import representation where exposed;
- private and preshared keys redacted from ordinary `Debug`/`Display`;
- no key material in tracing fields or kernel-error context strings;
- zeroization where practical and supported by selected secret types.

Prefer well-reviewed key primitives from the selected WireGuard ecosystem rather than implementing cryptographic arithmetic from scratch.

Tests MUST include known-valid key parse/derive fixtures without embedding real user secrets.

## 6. Desired/observed WireGuard types

Complete the M001 shells.

### Desired device state

At minimum:

- interface locator;
- server private-key secret reference/material at the privileged boundary;
- listen port;
- peer collection.

### Desired peer state

At minimum:

- `PeerId` correlation outside the kernel;
- peer public key;
- optional preshared key;
- server-side AllowedIPs;
- optional persistent keepalive;
- optional configured endpoint only if required.

### Observed peer state

At minimum:

- public key;
- current AllowedIPs;
- keepalive;
- configured/observed endpoint as exposed by kernel API;
- latest handshake;
- RX bytes;
- TX bytes.

Observed telemetry must not be persisted as desired configuration by this subsystem.

## 7. Mutation semantics

WireGuard Generic Netlink supports operations that can unintentionally replace more state than intended if flags/peer updates are modeled poorly.

M003 MUST make replacement semantics explicit.

Requirements:

- distinguish add/update/remove peer;
- distinguish “leave existing value” from “clear value”;
- distinguish “replace AllowedIPs for this peer” from “append”;
- do not use whole-device replace-peers for an ordinary single-peer edit unless desired state explicitly authorizes replacement and preservation has been checked;
- validate duplicate peer keys before mutation;
- validate duplicate/overlapping server-side AllowedIPs according to wg-basic policy before mutation.

The backend should be usable later by M004's reconciliation engine without hidden destructive defaults.

## 8. Privileged protocol extension

Extend M002 with domain-specific operations.

Reasonable operation shapes include:

- `ObserveWireGuardDevice { interface }`;
- `ApplyWireGuardDevice { interface, patch }`.

A more granular peer operation set is acceptable if it makes ownership/verification clearer.

Protocol requirements:

- bounded peer/AllowedIP counts;
- server/private/preshared key fields treated as secret values by logging/diagnostics;
- privileged service revalidates key/address/conflict rules;
- no raw netlink attributes;
- no arbitrary interface kind mutation.

M003 protocol additions should be version-compatible with M002 rather than inventing a second socket.

## 9. Live telemetry semantics

Expose:

- latest handshake as optional time;
- RX/TX as unsigned counters;
- endpoint as optional observed socket address.

Do not synthesize “connected” as a durable truth. Presentation layers may later derive a status from handshake age, but M003 provides kernel facts.

Counter wrap/reset/device recreation behavior should be documented rather than converted into invented monotonic totals.

## 10. Error taxonomy

Distinguish:

- interface missing;
- interface exists but is not WireGuard;
- permission/capability failure;
- invalid key;
- invalid/conflicting peer policy;
- netlink/kernel rejection;
- unsupported backend/kernel behavior;
- protocol validation error.

Retain safe kernel diagnostics while redacting secret payloads.

## 11. Integration fixture strategy

M003 closure requires a real Linux kernel WireGuard path.

A privileged/rootful integration harness may use host tooling for fixture-only namespace/link/address/route setup because production RTNETLINK ownership is M004.

The harness MUST NOT use `wg` or `wg-quick` to configure the WireGuard device/peers under test.

Suggested topology:

```text
namespace A                         namespace B
veth-a <--------------------------> veth-b
wg-a                                wg-b
10.200.0.1/24                       10.200.0.2/24
```

Fixture tooling may:

- create namespaces/veth;
- create WireGuard link type;
- assign underlay/tunnel fixture addresses/routes needed solely to make traffic possible.

Production wg-basic backend must:

- generate/set WireGuard keys;
- set listen ports;
- configure peers/AllowedIPs/endpoints;
- observe resulting device/peer state.

Then send traffic and verify:

- handshake becomes non-empty;
- RX/TX counters increase;
- observed endpoint is populated.

If network namespace WireGuard placement requires moving links between namespaces, document exact setup.

## 12. Preservation tests

The fixture must include at least one preservation case:

- pre-existing peer on the same WireGuard device not owned by the mutation under test; or
- an unrelated WireGuard device.

A single-peer update MUST NOT delete the preservation peer/device.

If wg-basic later adopts full desired-device ownership, that replacement behavior belongs to M004 reconciliation and must be explicit.

## 13. Focused tests

Unit:

- key parse/export/derive;
- secret formatting;
- DesiredPeer validation;
- duplicate public-key detection;
- AllowedIP conflict detection;
- patch tri-state/clear/unchanged semantics;
- protocol encode/decode for M003 operations;
- kernel-error redaction.

Integration:

- observe configured fixture device;
- set listen port/private key;
- add peer;
- update keepalive/AllowedIPs;
- remove peer;
- preservation fixture;
- real handshake and telemetry.

## 14. Runtime dependency guard

Production source MUST NOT invoke:

- `wg`;
- `wg-quick`;
- `ip` for WireGuard configuration.

The integration harness may invoke `ip` for fixture plumbing only and that boundary must be obvious in source layout.

Do not add shell pipelines to tests where direct argv invocation suffices.

## 15. Verification

Routine Rust gates remain:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Kernel integration command should be one documented target/script, for example:

```text
sudo -E cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture
```

The exact feature/name is implementation-defined.

The integration harness MUST check prerequisites and skip/fail with an explicit reason rather than silently pretending kernel evidence ran.

## 16. Documentation

Update:

- `architecture/overview.md`;
- add `architecture/wireguard-control.md`;
- privilege protocol operation reference;
- development instructions for rootful namespace tests;
- dependency decision rationale;
- current limitations: no production address/route/firewall management yet.

README should not yet claim a one-command functional VPN appliance.

## 17. Acceptance criteria

M003 closes only when:

1. one selected Rust backend controls kernel WireGuard without runtime `wg`/`wg-quick`;
2. server key/listen configuration round-trips from kernel observation;
3. peer add/update/remove behavior is explicit and tested;
4. AllowedIPs replacement semantics cannot silently destroy unrelated state;
5. private/preshared keys are secret-safe;
6. M003 operations use the M002 typed privileged protocol;
7. real Linux namespace peers complete a WireGuard handshake;
8. observed handshake/endpoint/RX/TX reflect real traffic;
9. preservation fixtures prove unrelated state survives;
10. routine/MSRV verification passes;
11. no unresolved high/medium security/correctness finding remains.

## 18. Stop conditions

Stop and research/ADR rather than forcing implementation if:

- current high-level crates cannot represent safe peer patch semantics;
- selected dependency raises MSRV materially or pulls an unjustified runtime;
- kernel integration requires production code to shell out;
- reliable secret redaction cannot be maintained through the selected API;
- peer preservation requires redesigning M004's desired-state ownership;
- the target runner cannot provide real kernel evidence.

## 19. Closure evidence

Record:

- backend candidates/research matrix and selected dependency versions/licenses;
- dependency tree/footprint notes;
- exact protocol additions;
- key-handling design;
- unit test results;
- namespace fixture topology;
- real handshake evidence;
- telemetry before/after traffic;
- preservation result;
- runtime command-execution guard result;
- hosted/rootful CI or equivalent Linux evidence;
- recommendation on M004 readiness.

M004 becomes `ready` only after strict M003 closure.
