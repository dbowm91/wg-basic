# Network Control M001 — Repository, Domain, and Runtime-Role Foundation

Status: closed

Repository baseline: `539b06182a311e2cf71912cd54356bf80312e603`

Source roadmap:

- `plans/subsystems/network-control-roadmap.md#7-milestone-m001--repository-domain-and-runtime-role-foundation`
- `plans/002-long-term-roadmap.md#3-phase-1--repository-and-domain-foundation`

Canonical requirements:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/003-planning-process.md`
- `plans/adr/001-linux-native-control-plane.md`

Primary class: infrastructure / invariant

## 1. Objective

Create the minimal Rust production foundation for wg-basic without performing host-network mutation.

The milestone establishes package/toolchain policy, executable/runtime-role dispatch, typed domain values, validation, secret-safe formatting, error categories, test seams, and baseline verification so later network milestones have stable contracts to build on.

## 2. Why this milestone is ready

There are no hard implementation dependencies.

The repository is planning-only at the baseline. Product scope, terminology, Linux-first architecture, and privilege-separation decision are already canonical.

No kernel-control dependency needs to be selected yet.

## 3. Non-goals

M001 MUST NOT:

- create or configure a WireGuard interface;
- open netlink sockets for mutation;
- alter links, addresses, routes, nftables, or sysctls;
- implement the privileged Unix socket protocol;
- start an HTTP server;
- add SQLite;
- implement authentication;
- generate QR codes;
- implement self-update/install;
- add Docker files as canonical deployment;
- create generic command/shell execution helpers “for later.”

## 4. Repository/package shape

Prefer the smallest shape that cleanly supports a library plus one executable.

A root Rust package containing `src/lib.rs` and `src/main.rs` is acceptable and preferred unless implementation evidence demonstrates that an immediate workspace split provides a concrete ownership benefit.

Do not create a many-crate workspace speculatively.

The foundation SHOULD allow later modules approximately along these boundaries:

```text
src/
  domain/
  error.rs
  cli/
  runtime/
  platform/
    linux/       # initially empty/read-only seams only
  protocol/      # contract placeholder only if useful
```

Exact names are implementation choices.

The library boundary should contain domain/validation contracts so integration tests do not need to invoke the CLI for every invariant.

## 5. Toolchain and package policy

Establish:

- Rust edition 2021 unless current dependency evidence strongly favors a newer edition without raising operational friction;
- MSRV Rust 1.89 to align with current Eggstack crates;
- checked-in `Cargo.lock`;
- workspace/package metadata and license;
- `unsafe_code = "deny"` at the broadest practical scope;
- Clippy baseline with warnings denied in verification;
- no default dependency on OpenSSL/system TLS;
- Linux as the only production-supported OS at this stage.

If the repository is expected to compile documentation/domain code on non-Linux hosts, use explicit `cfg(target_os = "linux")` boundaries and typed “unsupported platform” outcomes rather than pretending network support exists.

## 6. CLI/runtime-role contract

Create a small CLI skeleton with commands sufficient to preserve the target process topology.

At minimum represent:

- default/help/version behavior;
- `serve` role placeholder;
- `netd` role placeholder;
- `doctor` placeholder/read-only foundation if useful.

The placeholders MUST fail or report “not implemented” truthfully. They MUST NOT mutate networking.

Do not add dozens of future flags.

CLI parsing may use a small established crate such as Clap if justified by maintenance/ergonomics. The dependency decision should be recorded in the implementation report, not elevated to an ADR.

## 7. Domain types

Implement typed values sufficient for M002–M004 planning contracts.

### 7.1 Identifiers

Provide distinct newtypes for at least:

- `InterfaceId`;
- `PeerId`;
- `ClientId`.

Stable generation format is an implementation choice, but IDs MUST:

- not be derived from interface name, IP address, label, or database row;
- serialize/parse deterministically if serialization is introduced;
- have bounded length/representation.

Avoid introducing `InstallationId` unless a real consumer exists in this milestone.

### 7.2 Interface name

Define a validated Linux interface-name value or validation helper.

Requirements:

- reject empty names;
- honor Linux IFNAMSIZ semantics;
- reject embedded NUL/control characters;
- preserve exact accepted name;
- do not derive identity from it.

Whether to permit every kernel-valid punctuation character or intentionally narrow the user-facing subset must be documented and tested.

### 7.3 Address/prefix values

Use standard IP/address network primitives or a mature crate rather than hand-rolled CIDR parsing.

Represent:

- interface tunnel prefixes;
- peer/server AllowedIPs;
- client route prefixes.

Validation helpers must detect obvious conflicts required by later milestones, including duplicate client address assignment and invalid family/prefix relationships.

Do not implement a full allocator yet.

### 7.4 Keys and secrets

M001 does not need to select the M003 WireGuard control crate or implement X25519/WireGuard key derivation.

It DOES need a secret-handling policy and wrappers that prevent accidental disclosure.

If key byte wrappers are introduced:

- public key display may be explicit;
- private/preshared key wrappers MUST redact `Debug` and ordinary `Display`;
- secret equality/clone behavior should be deliberate;
- zeroization SHOULD be used when mature and practical, but do not claim that Rust heap copies are impossible unless the implementation proves it.

Do not store private keys in plain `String` fields that derive `Debug`.

### 7.5 Desired-state shells

Define enough typed state to prevent later API design from collapsing unrelated concerns.

Expected conceptual types:

- `DesiredInterface`;
- `DesiredPeer`;
- `ClientRoutePolicy`;
- `DesiredNetworkPolicy` or smaller forwarding/firewall placeholders;
- `ObservedInterface` / `ObservedPeer` shells only if M002/M003 needs them.

Keep firewall policy small; M005 owns its real semantics.

### 7.6 Reconciliation types

Create generic/minimal types only if they are already useful for later plans:

- mutation identifier/category;
- plan summary;
- apply disposition;
- verification disposition.

Do NOT invent a generic dynamic operation language.

## 8. Validation invariants

Focused validation should cover:

- IDs remain type-distinct;
- interface-name bounds;
- listen-port bounds where represented;
- valid IP network parsing;
- assigned client address belongs to managed tunnel prefix when that relationship is validated;
- duplicate client address detection in a desired interface aggregate;
- duplicate peer public key detection if keys are represented;
- server-side AllowedIPs and client route policy remain distinct fields/types;
- secret formatting cannot reveal secret bytes through ordinary Debug/Display.

Validation errors MUST be typed/actionable enough for future UI/API mapping.

## 9. Error model

Create an application error taxonomy that distinguishes at least:

- invalid input/domain state;
- unsupported platform/capability;
- I/O/runtime failure;
- protocol failure placeholder where useful;
- kernel/backend failure placeholder where useful;
- conflict/ownership failure.

Avoid one giant string error as the internal contract.

Libraries may use `thiserror` or equivalent if justified. Do not leak secrets into formatted source errors.

## 10. Logging/diagnostic foundation

If structured logging is introduced, use a small standard Rust approach such as `tracing`.

Requirements:

- no private/preshared key bytes in fields;
- no enrollment configuration material;
- stable high-level categories;
- CLI errors remain useful without requiring debug logs.

Logging is optional in M001 if no runtime behavior merits it; do not add a large subscriber stack solely for future use.

## 11. Platform boundary

Create an explicit Linux module boundary before M002.

Non-Linux behavior for network roles MUST fail with a typed unsupported-platform error or be compile-gated.

Do not hide Linux `cfg` checks throughout domain code.

M001 SHOULD NOT add netlink crates yet.

## 12. Test strategy

### Focused unit tests

Required:

- interface-name validation;
- identifier parse/generation properties;
- CIDR/address validation;
- duplicate/conflict validation represented by M001;
- secret Debug/Display redaction;
- CLI role parsing;
- non-mutating role placeholders.

Property tests MAY be used for parsers/value objects if they remain lightweight; they are not required.

### Mutation guard

Add a simple architectural/source guard only if it is cheap and meaningful, for example ensuring no `std::process::Command` exists in the initial production source.

Do not build a custom static-analysis framework.

The guard may later evolve when M005 intentionally considers a bounded internal `nft` backend.

## 13. Hosted CI

Add one small routine workflow for main/pull requests:

- formatting;
- check;
- Clippy;
- unit tests;
- MSRV check if practical without duplicating excessive compilation.

Do not add:

- release builds/artifacts;
- Docker builds;
- dependency-bot configuration;
- scheduled scanners;
- multi-platform matrices;
- network namespace tests before they exist.

Linux x86_64 hosted CI is sufficient for M001.

## 14. Documentation

Add/update:

- root `README.md` with truthful planning-stage product statement and non-container goal;
- `architecture/overview.md` describing only implemented M001 boundaries and planned links without claiming kernel behavior exists;
- `docs/development.md` or equivalent canonical local verification commands if useful;
- `AGENTS.md` with concise pointers to planning authority and verification commands.

Do not duplicate the full specification in README.

## 15. Expected verification

At minimum:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

If `cargo +1.89.0` is unavailable in the implementation environment, record it as not run and rely on hosted MSRV evidence before strict closure.

Also search production source for accidental command execution / raw secrets according to the implementation's chosen guard.

## 16. Acceptance criteria

M001 is complete when:

1. the Rust project builds from a clean checkout on supported Linux;
2. toolchain/MSRV/lint policy is explicit;
3. one executable represents future `serve` and `netd` roles without networking mutation;
4. core IDs/network domain values are typed and tested;
5. secret-bearing values cannot be accidentally printed through ordinary formatting;
6. server-side AllowedIPs and client route policy are separate;
7. Linux-specific code has one clear boundary;
8. no host-network mutation path exists;
9. routine CI verifies the M001 contract;
10. architecture/docs/registry agree.

## 17. Stop conditions

Stop and report instead of broadening scope if:

- a dependency requires raising MSRV materially above 1.89;
- a domain type cannot be defined without selecting a specific WireGuard backend;
- non-Linux compilation would require substantial abstraction work;
- implementation pressure suggests adding generic process execution or shell helpers;
- planning documents materially contradict the desired domain model.

## 18. Closure evidence required

The closure record must include:

- implementation commit(s);
- final package/crate/module inventory;
- dependency inventory with justification for non-trivial runtime dependencies;
- exact verification command outcomes;
- hosted CI result;
- secret-formatting tests;
- source/mutation guard result;
- known warnings/limitations;
- recommendation on M002 readiness.

M002 moves to `ready` only after this closure is accepted.
