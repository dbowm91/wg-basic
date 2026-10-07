# Network Control C001 — Post-Foundation Reconciliation and Module Decomposition

Status: ready

Repository baseline: `1b17d49bf208a7ef3b72f0028241ae77299fe207`

Source roadmap:

- `plans/subsystems/network-control-post-foundation-reconciliation-addendum.md`

Historical closure baseline:

- M005 final implementation/qualification: `c67fff82c92e7b27aead1e65ff775ca88b025150`
- post-closure planning head: `1b17d49bf208a7ef3b72f0028241ae77299fe207`
- CI run on current head: `37593450156` — all four jobs green

Primary class: corrective / polish / invariant preservation

## 1. Objective

Perform one contract-preserving cleanup before Phase 6 persistence and Phase 7 HTTP/service work add additional consumers.

The pass has two responsibilities:

1. reconcile stale documentation/CLI text with the implemented M001–M005 state;
2. split the largest modules into clearer internal ownership boundaries without changing wire contracts, network policy, or runtime behavior.

## 2. Current evidence

At the baseline:

- M001–M005 are strictly closed;
- current-head CI is green for routine Rust, kernel WireGuard, RTNETLINK reconciliation, and full network-control E2E;
- `src/reconcile.rs` is approximately 39 KiB / ~1,059 lines;
- `src/firewall.rs` is approximately 35 KiB / ~991 lines;
- `src/protocol/server.rs` combines socket ownership, authorization, lifecycle, dispatch, and error projection;
- README is largely current;
- `src/main.rs`, `architecture/privilege-boundary.md`, and `plans/registry.md` contain stale milestone-era wording.

No current evidence requires reopening M001–M005 semantics.

## 3. Non-goals

Do not:

- add or change persistence;
- add new protocol operations;
- bump `PROTOCOL_VERSION`;
- change serialized field names or enum variants;
- change socket ownership/mode/auth policy;
- alter route ownership or delete semantics;
- alter WireGuard patch semantics;
- alter nftables generated semantics, ownership markers, or limits;
- change forwarding teardown;
- replace dependencies;
- add HTTP/EggServe;
- add install/update behavior.

## 4. Work package A — Documentation and operator-text reconciliation

Correct present-tense drift in:

- `src/main.rs` help/comments;
- `architecture/privilege-boundary.md`;
- `architecture/overview.md` if any future-tense wording remains;
- `plans/registry.md`;
- subsystem status text that still describes closed work as future.

Required result:

A reader entering through README, architecture docs, CLI help, or registry must get one consistent statement:

- M001–M005 network control is implemented and qualified;
- persistence, HTTP/UI, install/update are not implemented;
- the runtime `nft` dependency is limited to firewall policy operations.

Do not rewrite historical closure records.

## 5. Work package B — Reconciliation module decomposition

Split `src/reconcile.rs` by responsibility while preserving imports/re-exports needed by current callers.

Target ownership:

- model/types;
- pure planning/diff;
- application service + locking + apply/verify;
- Linux backend remains isolated.

Requirements:

- `plan_managed_interface` remains pure;
- mutation ordering remains deterministic;
- apply continues to re-observe and verify;
- same installation-wide serialization semantics;
- all current error/status variants remain compatible;
- no public API break solely for aesthetics.

Add module-focused tests only where moving code exposes previously implicit boundaries. Do not rewrite the algorithm.

## 6. Work package C — Firewall module decomposition

Split `src/firewall.rs` by responsibility.

Target ownership:

- typed policy/validation;
- observation/planning;
- service/apply receipt;
- nft rendering/process execution/JSON normalization.

Requirements:

- exact table owner marker remains `wg-basic:m005:v1`;
- exact bounds remain unless correcting an obvious constant-location issue:
  - 64 prefixes;
  - 32 KiB nft input;
  - 256 KiB output per stream;
  - five-second timeout;
  - nft >= 0.9.0;
- same atomic whole-table replacement;
- same expression-level drift detection;
- same independent-firewall warning;
- same forwarding behavior.

If test helpers need visibility changes, prefer `pub(crate)` over public API expansion.

## 7. Work package D — Privileged protocol decomposition

Separate:

- authorization/peer credential policy;
- socket bind/stale-path/drop lifecycle;
- operation dispatch/error mapping;
- client request helper.

Preserve:

- four-byte big-endian length framing;
- 64 KiB frame bound;
- JSON wire representation;
- current protocol version;
- request correlation;
- one request per connection;
- sequential/bounded server behavior;
- two-second I/O timeout;
- 16-listener backlog/current concurrency semantics;
- early unauthorized-peer rejection.

Do not introduce async/concurrent request handling in this pass.

## 8. Work package E — Static guards

Keep or add inexpensive checks showing that refactoring did not cross architecture boundaries:

- production WireGuard/link/route control does not invoke `wg`, `wg-quick`, or `ip`;
- firewall process execution remains isolated to the nft backend;
- no `sh -c`, `bash -c`, or equivalent shell execution appears;
- privileged protocol has no generic exec/file-write/raw-netlink/raw-nft operation;
- secret wrappers continue to redact ordinary `Debug`/`Display`.

Prefer normal Rust tests or a small source assertion; do not add a bespoke lint framework.

## 9. Verification

Required routine checks:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Required rootful regression suite:

```text
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture

sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test network_reconcile -- --nocapture

sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test network_control_e2e -- --nocapture
```

Hosted CI must pass all four current jobs at the final C001 head.

## 10. Acceptance criteria

C001 closes only when:

1. stale current-state wording is reconciled;
2. reconcile/firewall/protocol ownership boundaries are visibly clearer;
3. no wire-format/protocol-version change occurred;
4. no network/firewall policy semantic change occurred;
5. no new runtime dependency was added without explicit necessity;
6. routine Rust/MSRV checks pass;
7. all current rootful integration suites pass;
8. diff review shows the change is predominantly moves/extractions plus documentation;
9. no new high/medium correctness/security finding remains.

## 11. Stop conditions

Stop and create a separate corrective if:

- refactoring exposes a behavioral defect that requires changing established network semantics;
- a protocol schema/version change appears necessary;
- current tests depend on module-private behavior in a way that would force public API expansion;
- splitting modules requires broad dependency inversion unrelated to Phase 6/7 readiness;
- a proposed cleanup changes nftables output or reconciliation ordering without a demonstrated defect.

## 12. Closure evidence

The closure record must include:

- before/after module inventory and approximate sizes;
- documentation drift corrected;
- public/wire API compatibility statement;
- dependency diff;
- routine/MSRV results;
- all three rootful integration results;
- current-head hosted CI run;
- source/static guard results;
- unresolved findings;
- recommendation whether Phase 6/7 implementation may proceed.