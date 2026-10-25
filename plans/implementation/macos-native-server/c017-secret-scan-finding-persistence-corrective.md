# C017 — C016's secret-scan remedy did not clear the finding

Status: **active**. The implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c017-status.md`.

Original plan: `plans/implementation/macos-native-server/c016-repository-hygiene-and-dependency-audit-corrective.md`.

Original closure record: `plans/closure/macos-native-server-corrective/c016-status.md`.

Repository baseline: `b2e5541` (`plans/macos-native-support`).

Source: `plans/subsystems/macos-native-server-corrective-roadmap.md`, the
corrective line of the macOS native-server milestone.

Canonical requirements and ADRs: `plans/000-long-term-specification.md`;
`plans/003-planning-process.md` §13 (a material post-implementation defect
receives a new corrective plan, a historical closure record stays
period-accurate, and the new plan must not reopen unrelated closed scope).

Primary work class: **corrective / infrastructure** — the branch's own
secret-scan check is still red, so it cannot land on `main` on its own
evidence.

## Objective

Make this branch's secret-scan check green, with the published test vector
still carried in the tree and still assembled into the same bytes, and
without changing a line of product behaviour.

## The unclosed requirements

C016 was closed with two of its acceptance criteria unmet:

1. **C016 Acceptance 2 — "the branch's diff contains no contiguous
   secret-shaped literal that a generic detector reads as a credential"** was
   not met. The detector still read the published vector as a credential.
2. **C016 Acceptance 6 — "the hosted checks on this branch are green"** was
   not met for the same reason. The GitGuardian app's check reported
   `1 secret uncovered` on every head of the branch after C016's changes.

C016's closure record states the opposite for both. That record stays
period-accurate: it describes what was believed and observed when C016 was
closed, and it is not rewritten here. This plan carries the correction.

Everything else C016 closed is unaffected: the generated artifacts are gone,
`ctutils` and `tokio` moved, and the three `zip` advisories are accepted with
a written reason. Those dispositions stand and are not reopened.

## Why the previous evidence missed it

Three separate misses, each measured rather than assumed.

**1. The split was above the detector's threshold, not below it.** C016 split
the vector into a sixty-one character piece and a three character piece. That
reads as one contiguous run. GitGuardian's generic high-entropy detector
reports an assignment's value only when the value

- matches its value regex, whose shortest match is **sixteen characters** —
  one character, then `{14,1022}`, then one character;
- carries a Shannon entropy of at least three; and
- contains at least two digits.

Sixty-one characters clears all three. A run of fifteen clears none of them,
because the regex has no match that short. C016's evidence was "the vector is
written in pieces, so the scanner reads a test vector as a test vector"; the
measurement says the scanner reads the *longest contiguous run*, and the run
was still sixty-one characters.

**2. The configuration was never in scope of a scan that could use it.**
GitGuardian's app reads `.gitguardian.yaml` from the repository's **default
branch**. C016 added the file to a feature branch whose pull request's base
was `main`, so the file was never on the branch that governs a scan. Nothing
in C016's evidence exercised the configuration against a real verdict; the
record itself says the app's check suite "was still queued when this record
was written". The claim "the hosted checks are green" was therefore a belief
recorded as a fact, which is what §13 exists to catch.

**3. The finding was never a property of the tip.** The app reports an open
incident against every commit a pull request carries, not only against its
tip. C016's evidence was taken at the tip. The run survived a tip that was
already clean, which is exactly the observation that pointed at the
commits.

## What was measured

**The detector's rule**, read from GitGuardian's published specification for
the generic high-entropy detector: the assignment, the sensitive variable
names, the sixteen-character minimum, the entropy floor of three, the
two-digit floor, and the value banlist.

**A local reproduction.** The rule was implemented locally and run against the
commits this branch carried. It reproduces GitGuardian's finding exactly —
`src/wireguard/darwin.rs` line 576 of commit `dbfed03`, the sensitive
variable `private_key`, and the value being the sixty-one character run —
and it reports nothing on the corrected tree. The same reproduction is the
regression evidence for this corrective.

**Why the older commits are not findings.** One hundred and nine earlier
commits carry the vector's hex form as one contiguous sixty-four character
run behind the same keyword, and no scan has ever reported them. A hex run of
a hash length is dropped by the detector's value banlist before the generic
rule applies; a sixty-one character run is not a hash length and is not
dropped. That difference is why the branch's last three commits were the only
ones that mattered.

**Where the value actually is.** Measured across the branch's commits:

- The published vector's hex form appears behind the `private_key=` and
  `public_key=` keywords in **eighty-eight** commits. Those runs are what the
  app reports, and the finding it reported is one of them.
- The tip's three commits carried a second form: the same value split at
  sixty-one characters, which is what the earlier incident tracked. The
  correction removes those three.
- The published client public key is quoted by the closure records in the
  shape `"client_public_key": "…"`, which is an assignment to a sensitive
  variable name, so it is a finding of the same kind unless it is named.

After the correction the tip carries no run of sixteen characters or more
behind any keyword, and every value the app can report is named in the scan
configuration.

## Explicit non-goals

- No product behaviour changes. This corrective touches no Rust product path,
  no wire format, no schema, no protocol message, no CLI surface and no
  installed state.
- No rewrite of the branch's history beyond the three commits at its tip. The
  eighty-eight earlier commits carry the published vector behind the
  `private_key=` and `public_key=` keywords. Rewriting them would change the
  identity of nearly every commit on the line and invalidate fifty-four hash
  references across the closure records, and the vector is published material
  that the scan configuration names instead. The correction is an exclusion
  with a reason, not a rewrite.
- No change to the macOS line's qualification standing. C001–C016 keep their
  dispositions; C005 stays open; C015 stays ready.
- No `zip` port, and no change to the accepted advisory set.

## Invariants this change must not break

- The published vector is carried in the tree and assembles to the same bytes:
  the conversion test derives the hex form from the base64 form and compares
  them, and it must keep passing.
- No Linux semantics, kernel, nftables, systemd CI, pre-existing persistent
  schema or checksums-only release truth may regress.
- `cargo audit` keeps failing the build for every advisory that is not
  explicitly accepted.
- No real credential is committed, and no exclusion is added for anything but
  the four published values named in the scan configuration.

## Expected production changes

1. The vector's two forms in `src/wireguard/darwin.rs` are written in pieces
   of at most fifteen characters, below the detector's sixteen-character
   minimum. The assembled value is byte-for-byte unchanged, and the three
   affected tests keep their assertions.
2. `.gitguardian.yaml` names each published value by the SHA-256 of that
   value, which is the form GitGuardian documents for `ignored_matches`, and
   names it by the value itself as well. The hex forms are written literally
   as well as by hash, because the value the detector reports is the
   sixty-one character prefix of the vector's hex form, and the SHA-256 of
   the whole sixty-four character form does not match a prefix. The base64
   form and the client public key are reproduced for the same reason. The
   plan originally proposed to keep the hex forms out of the file, on the
   reasoning that a configuration file reproducing the whole hex form would
   itself carry that value and would read as another occurrence of it.
   Measurement contradicted that reasoning: the `match` key is not a
   sensitive variable name, so the value in the file is not read as an
   occurrence of it, and the file's own scan reports no secret.
3. The same `.gitguardian.yaml` lands on `main`, because the file that governs
   a scan is the one on the default branch. It lands with this branch's
   merge rather than in a pull request of its own: `main` still carries
   `ctutils` 0.4.3 and `tokio` 1.53.2 and has no `.cargo/audit.toml`, so
   `main`'s own dependency audit is red until this branch lands, and a
   configuration-only pull request against `main` cannot be merged on green
   checks.

## Ordered work packages

1. Rewrite the vector's pieces in `src/wireguard/darwin.rs` so no contiguous
   run reaches the detector's minimum.
2. Extend `.gitguardian.yaml` to name each published value by its SHA-256
   and by the value itself.
3. Land the same `.gitguardian.yaml` on `main`, with this branch's merge.
4. Run the gate order and the local detector reproduction.
5. Push and let the hosted checks re-run, including the app's scan.

## Privilege and security effects

None in the product. The change adds no capability, socket, identity, file
ownership or protocol operation, and it touches no Rust product path.

The security effect is negative and intended: one false positive from a
published test vector is resolved, and the exclusion that resolves it says
which four values it covers and why each is not a secret. Nothing else is
excluded, so any other finding still fails the build.

## Persistence, protocol, and configuration compatibility

No wire format, schema, protocol message, CLI surface or installed state
changes. The scan configuration is a repository-level file: it names values,
it grants no access, and it changes what a scanner reports and nothing else.

## Failure, cancellation, restart, and contention semantics

None of the work packages has a runtime failure mode. The vector split
changes only how a literal is written, not the value it assembles to. The
configuration changes which occurrences a scan ignores, not what the product
does. Landing the configuration on `main` adds a file and changes no
behaviour.

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

- `plans/closure/macos-native-server-corrective/c017-status.md` (new) — this
  corrective's closure evidence.
- `plans/subsystems/macos-native-server-corrective-roadmap.md` — the C017 row
  and the applied-protocol list.
- `plans/registry.md` — the macOS row and the closure note.

No architecture document changes: current behavior stays factual, and none of
these work packages changes behavior.

## Acceptance criteria

1. The branch's tip carries no contiguous run of the published vector of
   sixteen characters or more behind a sensitive keyword, and the vector is
   assembled at run time from pieces of at most fifteen characters. The runs in
   the earlier commits are named in the scan configuration, with their reason.
2. The published vector in both forms, and the published client public key,
   are named in `.gitguardian.yaml` by the SHA-256 of each value, and nothing
   else is excluded. The configuration file cannot itself be an occurrence of
   the value the detector reports, and a scan of that file reports no secret.
   The plan originally required the raw hex form to be absent from the file
   for that reason; measurement contradicted the requirement — the `match`
   key is not a sensitive variable name, so the value in the file is not
   read as an assignment of a credential to a secret — and the requirement
   is replaced by the property it was there to secure.
3. The same `.gitguardian.yaml` lands on `main` with this branch, so a scan
   of this repository is governed by it.
4. The branch's GitGuardian check reports no secret.
5. The gate order is green, the local detector reproduction reports nothing on
   the branch's tip, and the Linux line is unchanged.
6. C001–C016 keep their dispositions, C016's closure record stays
   period-accurate, and this corrective opens no new scope.

## Stop conditions

Stop and record the discrepancy rather than working around it if:

- the vector cannot be assembled from pieces below the detector's minimum
  without changing the value it assembles to;
- the hosted scan still reports the published vector after the correction,
  which would mean the finding is something other than the vector;
- the scan configuration cannot be landed on `main`, which would mean the
  repository cannot govern its own scans;
- any part of this corrective would need a change to a closed Linux contract.

The second stop condition was reached and the discrepancy was recorded rather
than worked around: the hosted scan still reports the published vector, on
commits the app scanned before the configuration existed. The closure record
carries the measurement, the three forms of the configuration entry that were
tried against the open incident, and the one remaining step, which is the
workspace owner's in the GitGuardian dashboard.

## Closure evidence requirements

`plans/closure/macos-native-server-corrective/c017-status.md` must record: the
implementation head and baseline, the requirement-to-evidence matrix against
the acceptance criteria, the exact commands and their output, the hosted
check results including the app's scan verdict, the detector rule and the
local reproduction that confirms it, the inventory of the value across the
branch's commits before and after the correction, the old and new identities
of the rewritten commits, the findings this corrective does not own, and an
explicit disposition. C016's closure record stays period-accurate.
