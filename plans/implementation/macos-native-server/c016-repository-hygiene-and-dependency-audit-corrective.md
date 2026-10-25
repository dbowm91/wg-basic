# C016 — The branch carries generated artifacts, a secret-scan false positive, and a failing dependency audit

Status: **active**. The implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c016-status.md`.

Repository baseline: `b2e5541` (`plans/macos-native-support`).

Source: `plans/subsystems/macos-native-server-corrective-roadmap.md`, the
corrective line of the macOS native-server milestone. Raised by the
maintainer's decision of 2026-10-25 that this line is cleaned before it merges
onto `main`.

Canonical requirements and ADRs: `plans/000-long-term-specification.md`;
ADR-008 (macOS headless platform backends); `plans/003-planning-process.md`
§13 (a material post-implementation defect receives a new corrective plan, and
a historical closure record stays period-accurate).

Primary work class: **corrective / infrastructure** — the branch's own
repository hygiene and supply-chain checks are red, so it cannot land on
`main` on its own evidence.

## Objective

Make this branch's repository state clean enough to merge onto `main`, with
every check that runs on it green, and without changing a line of product
behaviour.

Four things stand in the way, and all four were measured rather than assumed:

1. **Generated artifacts are committed.** The branch carries 530 files under
   `.codegg/` — 5.5 MB of AI session tool-call records (`context_artifacts`,
   `runs`, `research`, `test-runs`, and a `sessions.db`) — plus a macOS
   `.DS_Store` committed by `b2e5541` ("chore: add .DS_Store"). No source
   file, test, plan, architecture document or workflow references any of
   them.
2. **The secret-scan check is red.** GitGuardian reports "1 secret uncovered"
   across the branch's 108 commits. The one finding is the published
   WireGuard key-conversion vector `6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=`,
   re-typed as one contiguous base64 string in a new Darwin test. The same
   vector already ships in `src/domain/keys.rs` on `main`; it is a test vector
   that belongs to no host and authenticates nothing.
3. **The dependency audit is red.** `cargo audit` over the committed
   `Cargo.lock` reports four vulnerabilities and one allowed warning:
   `ctutils` 0.4.3 (RUSTSEC-2026-0385, non-constant-time mask generation and
   `u128` comparisons), `tokio` 1.53.2 (RUSTSEC-2026-0386, `AsyncFd::new` and
   related constructors violating I/O safety — a warning), and `zip` 6.0.0
   three times (RUSTSEC-2026-0367, RUSTSEC-2026-0368, RUSTSEC-2026-0369 —
   SUID/SGID preservation on extraction, symlinks escaping the destination
   directory, and Unix permissions applied through symlinks; the last is
   critical at CVSS 9.1).
4. **The branch's CI is red on two of its jobs** because of (2) and (3).

## Explicit non-goals

- No product behaviour changes. This corrective touches no Rust product path,
  no wire format, no schema, no protocol message, no CLI surface and no
  installed state.
- No change to the macOS line's qualification standing. C001–C014 keep their
  dispositions; C005 stays open; C015 stays ready. Nothing here narrows or
  widens them.
- No `zip` major-version port inside this repository. `zip` is not a direct
  dependency here and the pin that holds it lives in another repository; see
  "The `zip` advisories" below.
- No reimplementation of the release manifest projection. The `eggup-eggpack`
  dependency is exact-pinned because the release pipeline and this product
  must agree on one projection.

## Current repository evidence

**The dependency graph.** The audited crates reach this product as follows:

| Crate | Path | Movable here? |
|---|---|---|
| `ctutils` 0.4.3 | `digest` 0.11.3, `phc` 0.6.1 → `ctutils ^0.4` | yes — a patch bump |
| `tokio` 1.53.2 | direct (`tokio = { version = "1.44", … }`), plus `eggserve-server`, `hyper`, `netlink-sys`, `nl-wireguard`, `rtnetlink` | yes — a minor bump |
| `zip` 6.0.0 | `eggup-eggpack` → `eggup-archive` → `zip` | **no** — see below |

**Why `zip` cannot be bumped in this repository.** `eggup-archive` requires
`zip = "^6.0.0"` in every published version (0.1.2, 0.1.3 and 0.2.0), and
`eggup-eggpack` depends on `eggup-archive` unconditionally. `eggup-eggpack` is
exact-pinned in `Cargo.toml` as `=0.1.3`. No lockfile in this repository can
therefore resolve `zip` 9.x, which is where the fix for all three advisories
lives (`zip` 9.1.0 is published).

**Why the `zip` exposure is bounded here.** All three advisories describe
archive *extraction*. This product never extracts an archive. Its update path
acquires a signed release binary, verifies its size and SHA-256 digest, and
runs it through `eggup_core::run_bounded`; its use of `eggup-eggpack` is
limited to `project_json` and `install_ids`, which project and validate
release manifests and perform no I/O. The vulnerable entry points
(`ZipArchive::extract`, `ZipStreamReader::extract`) are unreachable from this
product. `eggup-eggpack`'s own documentation describes extraction as a step
the **caller** performs, and this product is not that caller.

**What would clear `zip`.** An `eggup-archive` release that allows `zip` 9,
followed by a bump of the `eggup-eggpack` pin. The port is small: `zip` 9.1.0
still exposes `ZipArchive::extract`, `by_index` and `file_names`, which is the
whole surface `eggup-archive` uses.

## Invariants this change must not break

- No Linux semantics, kernel, nftables, systemd CI, pre-existing persistent
  schema or checksums-only release truth may regress.
- The release manifest projection contract between the release pipeline and
  this product stays single-sourced.
- `cargo audit` keeps failing the build for every advisory that is not
  explicitly accepted; an accepted advisory carries a written justification.
- No secret-shaped literal is introduced into the diff, and no real credential
  is committed.

## Expected production changes

1. `.codegg/` and `.DS_Store` are removed from the tree and added to
   `.gitignore`. Nothing else references them.
2. The Darwin UAPI test's published vector is written in two pieces with a
   comment saying what it is. The assertion is unchanged.
3. `ctutils` moves 0.4.3 → 0.4.5 and `tokio` moves 1.53.2 → 1.54.1 inside
   their existing semver requirements. `Cargo.toml` does not change; only
   `Cargo.lock` does.
4. `.cargo/audit.toml` accepts exactly the three `zip` advisories, with the
   reasoning above written next to them.

## Ordered work packages

1. Remove `.codegg/` and `.DS_Store`; ignore them.
2. Split the published vector in `src/wireguard/darwin.rs` and document it.
3. Bump `ctutils` and `tokio` in the lockfile.
4. Add `.cargo/audit.toml` with the three accepted `zip` advisories and their
   justification.
5. Run the gate order and `cargo audit` locally.
6. Push and let the hosted checks re-run.

## Privilege and security effects

None in the product. The change adds no capability, socket, identity, file
ownership or protocol operation, and it touches no Rust product path.

The security effect is negative and intended: 5.5 MB of agent transcripts and
a macOS metadata file leave the repository, one secret-scan false positive is
resolved, and two real dependency advisories are closed by version movement.
The three `zip` advisories remain open upstream and are accepted **with a
written reason**, not silently: they describe extraction that this product
does not perform, and the upstream release that clears them is named.

## Persistence, protocol, and configuration compatibility

No wire format, schema, protocol message, CLI surface or installed state
changes. The two lockfile movements are within existing semver requirements.
The accepted advisories do not change what the product does.

## Failure, cancellation, restart, and contention semantics

None of the four work packages has a runtime failure mode. Removing tracked
files does not change any build input — no source, test, plan or workflow
referenced them. The vector split changes only how a literal is written, not
the value. The lockfile movements are version moves inside existing
requirements. The audit configuration changes which advisories are reported,
not what is built.

## Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo audit
git diff --check
```

## Documentation updates

- `plans/closure/macos-native-server-corrective/c016-status.md` (new) — this
  corrective's closure evidence.
- `plans/subsystems/macos-native-server-corrective-roadmap.md` — the C016 row
  and the applied-protocol list.
- `plans/registry.md` — the macOS row and the closure note.

No architecture document changes: current behavior stays factual, and none of
these work packages changes behavior.

## Acceptance criteria

1. The tree carries no `.codegg/` file and no `.DS_Store`, and `.gitignore`
   keeps them out.
2. The branch's diff contains no contiguous secret-shaped literal that a
   generic detector reads as a credential.
3. `cargo audit` exits zero over the committed lockfile, and the only
   accepted advisories are the three named `zip` ones, each with its reason
   and its clearing condition in `.cargo/audit.toml`.
4. `ctutils` and `tokio` are at versions without an advisory.
5. The gate order is green, and the Linux line is unchanged.
6. The hosted checks on this branch are green.
7. C001–C015 keep their dispositions and this corrective opens no new scope.

## Stop conditions

Stop and record the discrepancy rather than working around it if:

- removing the generated artifacts turns out to break a build input, a
  workflow or a qualification fixture;
- the `ctutils` or `tokio` movement turns out to need a manifest change or
  an API port;
- the audit would only go green by ignoring an advisory beyond the three
  named `zip` ones;
- GitGuardian's check stays red after the vector is split, which would mean
  the finding is something other than the vector;
- any part of this corrective would need a change to a closed Linux contract.

## Closure evidence requirements

`plans/closure/macos-native-server-corrective/c016-status.md` must record: the
implementation head and baseline, the requirement-to-evidence matrix against
the acceptance criteria, the exact commands and their output, the hosted
check results, the dependency-graph evidence for the three `zip` advisories
and why they are unreachable from this product, the secret-scan finding and
its resolution, the before/after tree and lockfile inventory, the findings
this corrective does not own, and an explicit disposition. C001–C015's closure
records stay period-accurate.
